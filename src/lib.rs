use arc_swap::ArcSwap;
use crypto::{Direction, SessionKeys};
use pyo3::exceptions::PyException;
use pyo3::types::{PyDict, PyList, PySet};
use pyo3::{create_exception, IntoPyObjectExt};
use pyo3::{
    prelude::*,
    types::{PyBytes, PyTuple},
};
use routing::circuit::{Circuit, CircuitType};
use routing::exit::{ExitSocket, PeerFlag};
use routing::relay::RelayRoute;
use socket::{TunnelSettings, TunnelSocket};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    thread,
};
use tokio::net::TcpListener;
use tokio::sync::oneshot::Sender;

use crate::packet::is_cell;
use crate::payload::Address;
use crate::routing::table::RoutingTable;
use crate::socks5::Socks5Server;

mod crypto;
mod packet;
mod payload;
mod request_cache;
mod routing;
mod socket;
mod socks5;
mod speedtest;
mod stats;
mod util;

#[macro_use]
extern crate log;

create_exception!(ipv8_rust_tunnels, RustError, PyException);

#[pyclass]
pub struct Endpoint {
    addr: String,
    rt: Option<RoutingTable>,
    socks_servers: Arc<Mutex<HashMap<SocketAddr, Socks5Server>>>,
    tokio_shutdown: Option<Sender<()>>,
}

#[pymethods]
impl Endpoint {
    #[new]
    fn new(listen_addr: String, list_port: u16) -> Self {
        Endpoint {
            addr: format!("{}:{}", listen_addr, list_port),
            rt: None,
            socks_servers: Arc::new(Mutex::new(HashMap::new())),
            tokio_shutdown: None,
        }
    }

    fn open(&mut self, callback: PyObject, worker_threads: usize) -> PyResult<bool> {
        if self.rt.is_some() {
            return Err(RustError::new_err("Endpoint is already open"));
        }

        info!("Spawning Tokio thread");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let (handle_tx, handle_rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(worker_threads)
                .build()
                .unwrap();

            handle_tx
                .send(rt.handle().clone())
                .expect("Failed to send Tokio runtime handle");

            rt.block_on(async {
                shutdown_rx.await.expect("Error on the shutdown channel");
            });

            rt.shutdown_background();
            info!("Exiting Tokio thread");
        });

        let rt = handle_rx.recv().expect("Failed to get Tokio runtime handle");
        self.tokio_shutdown = Some(shutdown_tx);

        let settings = Arc::new(ArcSwap::from_pointee(TunnelSettings::new(callback, rt)));

        info!("Spawning socket task");
        let addr = self.addr.clone();
        let socks_servers = self.socks_servers.clone();
        let (rt_tx, rt_rx) = std::sync::mpsc::channel();
        settings.load().handle.spawn(async move {
            let Ok(socket_addr) = addr.parse() else {
                error!("Failed to parse socket address");
                return;
            };
            let Ok(socket) = util::create_socket_with_retry(socket_addr) else {
                error!("Failed to create Tokio socket");
                return;
            };
            info!("Tunnel socket listening on: {:?}", socket.local_addr().unwrap());

            let rt = RoutingTable::new(socket, settings.clone());
            rt_tx.send(rt.clone()).expect("Failed to send Tokio socket");

            let mut ts = TunnelSocket::new(rt, socks_servers);
            ts.listen_forever().await;
        });
        let Ok(rt) = rt_rx.recv() else {
            error!("Failed to get routing table");
            return Ok(false);
        };
        self.rt = Some(rt);
        Ok(true)
    }

    fn close(&mut self) -> PyResult<()> {
        info!("Shutting down rust endpoint");

        if let Some(shutdown) = self.tokio_shutdown.take() {
            if let Err(e) = shutdown.send(()) {
                error!("Unable to shutdown Tokio thread: {:?}", e);
            }
        }
        self.tokio_shutdown = None;
        self.rt = None;

        Ok(())
    }

    fn create_socks5_server(&mut self, port: u16, hops: u8) -> PyResult<u16> {
        let rt = self.get_routing_table()?;
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let socks_servers = self.socks_servers.clone();
        let rt = rt.clone();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();

        rt.settings.load().handle.spawn(async move {
            let listener = match TcpListener::bind(addr).await {
                Ok(listener) => listener,
                Err(e) => {
                    error!("TCP listener couldn't be created: {}", e);
                    return;
                }
            };
            let listen_addr = listener.local_addr().unwrap();
            info!("Socks5 server (hops={}) listening on: {:?}", hops, listen_addr);
            let mut server = Socks5Server::new(rt, hops);
            socks_servers.lock().unwrap().insert(listen_addr, server.clone());
            addr_tx.send(listen_addr).expect("Failed to send Socks5 server");
            let _ = server.listen_forever(listener).await;
        });

        let addr = addr_rx.recv().expect("Failed to get Socks5 server");
        Ok(addr.port())
    }

    fn set_udp_associate_default_remote(
        &mut self,
        address: &Bound<'_, PyTuple>,
        hops: u8,
    ) -> PyResult<()> {
        let rt = self.get_routing_table()?;
        let socket_addr = parse_address(address)?;
        for (_, server) in self.socks_servers.lock().unwrap().iter_mut() {
            if server.hops != hops {
                continue;
            }
            for associate in server.associates.lock().unwrap().values() {
                // Set peer_addr for the Socks5 socket if it hasn't been set yet.
                if associate.socket.peer_addr().is_err() {
                    let socket = associate.socket.clone();
                    rt.settings.load().handle.spawn(async move {
                        let _ = socket.connect(socket_addr).await;
                    });
                }
            }
        }
        Ok(())
    }

    fn get_associated_circuits(&mut self, port: u16, py: Python<'_>) -> PyResult<PyObject> {
        let rt = self.get_routing_table()?;
        let circuit_ids: Vec<u32> = rt
            .circuits
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, c)| {
                c.socket.is_some() && c.socket.as_ref().unwrap().local_addr().unwrap().port() == port
            })
            .map(|(_, c)| c.circuit_id)
            .collect();
        Ok(PyTuple::new(py, circuit_ids)?.into_any().unbind())
    }

    fn run_speedtest(
        &mut self,
        circuit_id: u32,
        test_time: u16,
        request_size: u16,
        response_size: u16,
        target_rtt: u16,
        callback: PyObject,
        callback_interval: u16,
    ) -> PyResult<()> {
        let rt = self.get_routing_table()?;
        rt.settings.load().handle.spawn(speedtest::run_test(
            circuit_id,
            rt.clone(),
            test_time,
            request_size,
            response_size,
            target_rtt,
            callback,
            callback_interval,
        ));
        Ok(())
    }

    fn get_peers_for_circuit(&mut self, circuit_id: u32, py: Python<'_>) -> PyResult<PyObject> {
        let rt = self.get_routing_table()?;
        let mut result = Vec::new();

        let guard = rt.circuits.lock().unwrap();
        let hops = match guard.get(&circuit_id) {
            Some(circuit) => circuit.goal_hops,
            None => return Ok(PyList::new(py, result)?.into_any().unbind()),
        };
        drop(guard);

        for (_, server) in self.socks_servers.lock().unwrap().iter() {
            if server.hops != hops {
                continue;
            }

            for associate in server.associates.lock().unwrap().values() {
                for (addr, cid) in associate.addr_to_cid.lock().unwrap().iter() {
                    if *cid == circuit_id {
                        let (host, port) = match addr {
                            Address::V4(addr) => (addr.ip().to_string(), addr.port()),
                            Address::V6(addr) => (addr.ip().to_string(), addr.port()),
                            Address::DomainAddress((host, port)) => {
                                (String::from_utf8_lossy(host).to_string(), *port)
                            }
                        };
                        let any_addr = vec![host.into_py_any(py)?, port.into_py_any(py)?];
                        result.push(PyTuple::new(py, any_addr)?.into_any().unbind());
                    }
                }
            }
        }
        Ok(PyList::new(py, result)?.into_any().unbind())
    }

    fn get_socks5_statistics(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let mut result = Vec::new();
        for (addr, server) in self.socks_servers.lock().unwrap().iter() {
            let item = PyDict::new(py);
            let _ = item.set_item("port", addr.port());
            let _ = item.set_item("hops", server.hops);
            let _ = item.set_item("associates", server.associates.lock().unwrap().len());
            result.push(item);
        }
        Ok(PyList::new(py, result)?.into_any().unbind())
    }

    fn get_socket_statistics(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let rt = self.get_routing_table()?;
        Ok(PyTuple::new(py, rt.stats.lock().unwrap().socket_stats.to_vec())?
            .into_any()
            .unbind())
    }

    fn get_message_statistics(
        &mut self,
        prefix: &Bound<'_, PyBytes>,
        py: Python<'_>,
    ) -> PyResult<PyObject> {
        let result = PyDict::new(py);

        let cid: [u8; 22] = match prefix.as_bytes().try_into() {
            Ok(b) => b,
            Err(_) => {
                warn!("Prefix with incorrect length");
                return Ok(result.into_any().unbind());
            }
        };

        if let Some(rt) = &self.rt {
            if let Some(stats) = rt.stats.lock().unwrap().msg_stats.get(&cid) {
                for (key, value) in stats.iter() {
                    let _ = result.set_item(key, value.to_vec());
                }
            }
        }
        Ok(result.into_any().unbind())
    }

    fn set_prefix(&mut self, prefix: &Bound<'_, PyBytes>, py: Python<'_>) -> PyResult<()> {
        let rt = self.get_routing_table()?;
        let mut new_settings = TunnelSettings::clone(rt.settings.load_full(), py);
        new_settings.prefix = prefix.as_bytes().to_vec();
        info!("Set tunnel prefix: {:?}", new_settings.prefix);
        rt.settings.swap(Arc::new(new_settings));
        Ok(())
    }

    fn set_prefixes(&mut self, py_prefixes: &Bound<'_, PyList>, py: Python<'_>) -> PyResult<()> {
        let mut prefixes = vec![];
        for py_prefix in py_prefixes.iter() {
            if let Ok(prefix) = py_prefix.extract::<Vec<u8>>() {
                prefixes.push(prefix);
            } else {
                error!("Failed to convert prefix, skipping");
            }
        }

        let rt = self.get_routing_table()?;
        let mut new_settings = TunnelSettings::clone(rt.settings.load_full(), py);
        new_settings.prefixes = prefixes;
        info!("Set community prefixes: {:?}", new_settings.prefixes);
        rt.settings.swap(Arc::new(new_settings));
        Ok(())
    }
    fn set_max_relay_early(&mut self, max_relay_early: u8, py: Python<'_>) -> PyResult<()> {
        let rt = self.get_routing_table()?;
        let mut new_settings = TunnelSettings::clone(rt.settings.load_full(), py);
        new_settings.max_relay_early = max_relay_early;
        info!("Set maximum number of relay early cells: {}", new_settings.max_relay_early);
        rt.settings.swap(Arc::new(new_settings));
        Ok(())
    }

    fn set_peer_flags(&mut self, py_peer_flags: &Bound<'_, PyAny>, py: Python<'_>) -> PyResult<()> {
        let mut peer_flags = HashSet::new();
        for py_peer_flag in py_peer_flags.downcast::<PySet>()? {
            peer_flags.insert(match py_peer_flag.extract::<u16>()? {
                1 => PeerFlag::Relay,
                2 => PeerFlag::ExitBt,
                4 => PeerFlag::ExitIpv8,
                8 => PeerFlag::SpeedTest,
                32768 => PeerFlag::ExitHttp,
                f => {
                    warn!("Skipping invalid peer flag: {}", f);
                    continue;
                }
            });
        }

        let rt = self.get_routing_table()?;
        let mut new_settings = TunnelSettings::clone(rt.settings.load_full(), py);
        new_settings.peer_flags = peer_flags;
        info!("Set peer flags: {:?}", new_settings.peer_flags);
        rt.settings.swap(Arc::new(new_settings));
        Ok(())
    }

    fn set_exit_address(&mut self, address: &Bound<'_, PyTuple>, py: Python<'_>) -> PyResult<()> {
        let exit_addr = parse_address(address)?;
        let rt = self.get_routing_table()?;
        let mut new_settings = TunnelSettings::clone(rt.settings.load_full(), py);
        new_settings.exit_addr = exit_addr;
        info!("Set exit address: {:?}", new_settings.exit_addr);
        rt.settings.swap(Arc::new(new_settings));
        Ok(())
    }

    fn get_address(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let rt = self.get_routing_table()?;
        let addr = rt.socket.local_addr().unwrap();
        let ip = addr.ip().to_string().into_py_any(py)?;
        let port = addr.port().into_py_any(py)?;
        Ok(PyTuple::new(py, vec![ip, port])?.into_any().unbind())
    }

    fn get_byte_counters(&mut self) -> PyResult<PyObject> {
        let mut bytes_up = 0;
        let mut bytes_down = 0;
        if let Some(rt) = &self.rt {
            for (_, circuit) in rt.circuits.lock().unwrap().iter() {
                bytes_up += circuit.bytes_up;
                bytes_down += circuit.bytes_down;
            }
            for (_, relay) in rt.relays.lock().unwrap().iter() {
                bytes_up += relay.bytes_up;
                bytes_down += relay.bytes_down;
            }
            for (_, exit) in rt.exits.lock().unwrap().iter() {
                bytes_up += exit.bytes_up;
                bytes_down += exit.bytes_down;
            }
        }
        Python::with_gil(|py| Ok(PyTuple::new(py, vec![bytes_up, bytes_down])?.into_any().unbind()))
    }

    fn is_open(&mut self) -> bool {
        self.rt.is_some()
    }

    fn send(&mut self, address: &Bound<'_, PyTuple>, bytes: &Bound<'_, PyBytes>) -> PyResult<()> {
        let socket_addr = parse_address(address)?;
        let packet = bytes.as_bytes().to_vec();
        trace!("Sending packet with {} bytes to {}", packet.len(), socket_addr);
        self.send_to(packet, socket_addr)
    }

    fn send_cell(&mut self, address: &Bound<'_, PyTuple>, bytes: &Bound<'_, PyBytes>) -> PyResult<()> {
        let rt = self.get_routing_table()?;
        let socket_addr = parse_address(address)?;
        let packet = bytes.as_bytes().to_vec();
        let guard = rt.settings.load();

        if !is_cell(&guard.prefix, &packet) {
            error!("Trying to send invalid cell");
            return Ok(());
        }

        let circuit_id = u32::from_be_bytes(packet[23..27].try_into().unwrap());
        debug!("Sending cell({}) for {} to {}", packet[29], circuit_id, socket_addr);

        if let Some(circuit) = rt.circuits.lock().unwrap().get_mut(&circuit_id) {
            return Ok(match circuit.encrypt_outgoing_cell(packet, guard.max_relay_early) {
                Ok(cell) => self.send_to(cell, socket_addr)?,
                Err(e) => error!("Error while encrypting cell for circuit {}: {}", circuit_id, e),
            });
        }

        if let Some(exit) = rt.exits.lock().unwrap().get_mut(&circuit_id) {
            return Ok(match exit.encrypt_outgoing_cell(packet) {
                Ok(cell) => self.send_to(cell, socket_addr)?,
                Err(e) => error!("Error while encrypting cell for exit {}: {}", circuit_id, e),
            });
        }

        // When creating a multi-hop circuit, create(d) cells can be send without having routing information
        // about the circuit_id. Since they don't require crypto, we send them directly over the socket.
        if packet[22] == 0 && payload::NO_CRYPTO_PACKETS.contains(&packet[29]) {
            debug!("Sending create(d) cell({}) to {}", packet[29], socket_addr);
            return self.send_to(packet, socket_addr);
        }

        let relay_circuit_id = match rt.relays.lock().unwrap().get(&circuit_id) {
            #[rustfmt::skip]
            Some(relay) => if relay.rendezvous_relay { circuit_id } else { relay.circuit_id },
            None => return Ok(()),
        };
        if let Some(relay) = rt.relays.lock().unwrap().get_mut(&relay_circuit_id) {
            return Ok(match relay.encrypt_outgoing_cell(packet) {
                Ok(cell) => self.send_to(cell, socket_addr)?,
                Err(e) => error!("Error while encrypting cell for relay {}: {}", circuit_id, e),
            });
        }
        warn!("Not sending cell to {}", socket_addr);
        Ok(())
    }

    fn add_circuit(&mut self, circuit_id: u32, py_circuit: PyObject) -> PyResult<()> {
        let rt = self.get_routing_table()?;
        let mut circuit = Circuit::new(circuit_id);
        set_circuit_keys(&mut circuit, &py_circuit)?;
        rt.circuits.lock().unwrap().insert(circuit.circuit_id, circuit);
        Ok(())
    }

    fn update_circuit(&mut self, circuit_id: u32, py_circuit: PyObject) -> PyResult<()> {
        let rt = self.get_routing_table()?;
        if let Some(circuit) = rt.circuits.lock().unwrap().get_mut(&circuit_id) {
            set_circuit_keys(circuit, &py_circuit)?;
            set_stats(circuit.bytes_up, circuit.bytes_down, circuit.last_activity, &py_circuit)?;
        }
        Ok(())
    }

    fn update_circuit_stats(&mut self, circuit_id: u32, py_circuit: PyObject) -> PyResult<()> {
        let rt = self.get_routing_table()?;
        if let Some(circuit) = rt.circuits.lock().unwrap().get_mut(&circuit_id) {
            set_stats(circuit.bytes_up, circuit.bytes_down, circuit.last_activity, &py_circuit)?;
        }
        Ok(())
    }

    fn remove_circuit(&mut self, circuit_id: u32) -> PyResult<()> {
        let rt = self.get_routing_table()?;
        rt.circuits.lock().unwrap().remove(&circuit_id);
        Ok(())
    }

    fn add_relay(&mut self, circuit_id: u32, py_relay: PyObject) -> PyResult<()> {
        let rt = self.get_routing_table()?;
        Python::with_gil(|py| {
            let mut relay = RelayRoute::new(py_relay.getattr(py, "circuit_id")?.extract::<u32>(py)?);
            relay.direction = match py_relay.getattr(py, "direction")?.extract(py)? {
                0 => Direction::Forward,
                _ => Direction::Backward,
            };
            let binding = py_relay.getattr(py, "hop")?;
            let hop = binding.bind(py);
            relay.peer = addr_from_hop(&hop)?;
            relay.keys.push(keys_from_hop(&hop)?);
            relay.rendezvous_relay = py_relay.getattr(py, "rendezvous_relay")?.extract::<bool>(py)?;
            rt.relays.lock().unwrap().insert(circuit_id, relay);
            Ok(())
        })
    }

    fn update_relay_stats(&mut self, circuit_id: u32, py_relay: PyObject) -> PyResult<()> {
        let rt = self.get_routing_table()?;
        if let Some(relay) = rt.relays.lock().unwrap().get_mut(&circuit_id) {
            set_stats(relay.bytes_up, relay.bytes_down, relay.last_activity, &py_relay)?;
        }
        Ok(())
    }

    fn remove_relay(&mut self, circuit_id: u32) -> PyResult<()> {
        let rt = self.get_routing_table()?;
        rt.relays.lock().unwrap().remove(&circuit_id);
        Ok(())
    }

    fn add_exit(&mut self, circuit_id: u32, py_exit: PyObject) -> PyResult<()> {
        let rt = self.get_routing_table()?;
        let mut exit = ExitSocket::new(circuit_id);

        Python::with_gil(|py| {
            let binding = py_exit.getattr(py, "hop")?;
            let hop = binding.bind(py);
            exit.peer = addr_from_hop(&hop)?;
            exit.keys.push(keys_from_hop(&hop)?);
            rt.exits.lock().unwrap().insert(exit.circuit_id, exit);
            Ok(())
        })
    }

    fn update_exit_stats(&mut self, circuit_id: u32, py_exit: PyObject) -> PyResult<()> {
        let rt = self.get_routing_table()?;
        if let Some(exit) = rt.exits.lock().unwrap().get_mut(&circuit_id) {
            set_stats(exit.bytes_up, exit.bytes_down, exit.last_activity, &py_exit)?;
            return Python::with_gil(|py| {
                py_exit.setattr(py, "enabled", exit.socket.is_some())?;
                Ok(())
            });
        }
        Ok(())
    }

    fn remove_exit(&mut self, circuit_id: u32) -> PyResult<()> {
        let rt = self.get_routing_table()?;
        let mut exit_lock = rt.exits.lock().unwrap();
        if let Some(exit) = exit_lock.get(&circuit_id) {
            if let Some(handle) = &exit.handle {
                handle.abort();
                info!("Closed socket listen task for exit {}", exit.circuit_id);
            }
        }
        exit_lock.remove(&circuit_id);
        Ok(())
    }
}

impl Endpoint {
    fn send_to(&self, packet: Vec<u8>, address: SocketAddr) -> PyResult<()> {
        let rt = self.get_routing_table()?;

        match rt.socket.try_send_to(&packet, address) {
            Ok(_) => rt.stats.lock().unwrap().add_up(&packet, packet.len()),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // The socket is busy, so we'll retry on the Tokio thread and await it.
                let cloned_socket = rt.socket.clone();
                let cloned_stats = rt.stats.clone();
                rt.settings.load().handle.spawn(async move {
                    match cloned_socket.send_to(&packet, address).await {
                        Ok(_) => cloned_stats.lock().unwrap().add_up(&packet, packet.len()),
                        Err(e) => error!("Could not send packet to {}: {}", address, e.to_string()),
                    };
                });
            }
            Err(e) => error!("Could not send packet to {}: {}", address, e.to_string()),
        };
        Ok(())
    }

    fn get_routing_table(&self) -> Result<&RoutingTable, PyErr> {
        match &self.rt {
            Some(rt) => Ok(rt),
            None => Err(RustError::new_err("Endpoint is not open")),
        }
    }
}

#[pymodule]
#[pyo3(name = "rust_endpoint")]
pub fn ipv8_rust_tunnels(py: Python, module: &Bound<'_, PyModule>) -> PyResult<()> {
    env_logger::init();
    module.add("RustError", py.get_type::<RustError>())?;
    module.add_class::<Endpoint>()?;
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}

fn set_circuit_keys(circuit: &mut Circuit, py_circuit: &PyObject) -> PyResult<()> {
    circuit.keys.clear();
    circuit.exit_flags.clear();

    Python::with_gil(|py| {
        let hops = py_circuit.getattr(py, "_hops")?;
        let hops_list = hops.downcast_bound::<PyList>(py)?;
        for hop in hops_list {
            circuit.keys.push(keys_from_hop(&hop)?);
        }
        if !hops_list.is_empty() {
            let hop = hops_list.get_item(0)?;
            circuit.peer = addr_from_hop(&hop)?;
        }

        let hs_keys = py_circuit.getattr(py, "hs_session_keys")?;
        if !hs_keys.is_none(py) {
            circuit.hs_keys = vec![create_session_keys(&hs_keys.bind(py))?];
        }
        circuit.goal_hops = py_circuit.getattr(py, "goal_hops")?.extract::<u8>(py)?;
        circuit.circuit_type = match py_circuit.getattr(py, "ctype")?.extract::<String>(py)?.as_str() {
            "IP_SEEDER" => CircuitType::IPSeeder,
            "RP_SEEDER" => CircuitType::RPSeeder,
            "RP_DOWNLOADER" => CircuitType::RPDownloader,
            _ => CircuitType::Data,
        };
        for py_peer_flag in py_circuit
            .getattr(py, "exit_flags")?
            .downcast_bound::<PyList>(py)?
        {
            circuit.exit_flags.insert(match py_peer_flag.extract::<u16>()? {
                1 => PeerFlag::Relay,
                2 => PeerFlag::ExitBt,
                4 => PeerFlag::ExitIpv8,
                8 => PeerFlag::SpeedTest,
                32768 => PeerFlag::ExitHttp,
                f => {
                    warn!("Skipping invalid exit flag: {}", f);
                    continue;
                }
            });
        }
        Ok(())
    })
}

fn addr_from_hop(hop: &Bound<'_, PyAny>) -> PyResult<SocketAddr> {
    let address = hop.getattr("peer")?.getattr("address")?;
    parse_address(&address)
}

fn keys_from_hop(hop: &Bound<'_, PyAny>) -> PyResult<SessionKeys> {
    create_session_keys(&hop.getattr("keys")?)
}

fn create_session_keys(keys: &Bound<'_, PyAny>) -> PyResult<SessionKeys> {
    Ok(SessionKeys {
        key_forward: keys.getattr("key_forward")?.extract::<Vec<u8>>()?,
        key_backward: keys.getattr("key_backward")?.extract::<Vec<u8>>()?,
        salt_forward: keys.getattr("salt_forward")?.extract::<Vec<u8>>()?,
        salt_backward: keys.getattr("salt_backward")?.extract::<Vec<u8>>()?,
        salt_explicit_forward: keys.getattr("salt_explicit_forward")?.extract::<u32>()?,
        salt_explicit_backward: keys.getattr("salt_explicit_backward")?.extract::<u32>()?,
    })
}

fn set_stats(
    bytes_up: u32,
    bytes_down: u32,
    last_activity: u64,
    py_tunnel_obj: &PyObject,
) -> PyResult<()> {
    Python::with_gil(|py| {
        py_tunnel_obj.setattr(py, "bytes_down", bytes_down)?;
        py_tunnel_obj.setattr(py, "bytes_up", bytes_up)?;

        // Since Python may update the timestamp as well, ensure we don't lower it.
        let py_last_activity = py_tunnel_obj.getattr(py, "last_activity")?.extract::<f64>(py)? as u64;
        py_tunnel_obj.setattr(py, "last_activity", std::cmp::max(last_activity, py_last_activity))?;
        Ok(())
    })
}

fn parse_address(address: &Bound<'_, PyAny>) -> PyResult<SocketAddr> {
    let ip = address.get_item(0)?.extract::<String>()?;
    let port = address.get_item(1)?.extract::<u16>()?;
    match ip.parse::<IpAddr>() {
        Ok(addr) => Ok(SocketAddr::new(addr, port)),
        _ => Err(RustError::new_err("Invalid address")),
    }
}
