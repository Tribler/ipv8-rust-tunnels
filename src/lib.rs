use arc_swap::ArcSwap;
use crypto::{Direction, SessionKeys};
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::types::{PyList, PySet};
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
use tokio::net::UdpSocket;
use tokio::sync::oneshot::Sender;
use tokio::task::JoinHandle;

mod crypto;
mod payload;
mod routing;
mod socket;
mod socks5;
mod util;
#[macro_use]
extern crate log;

create_exception!(ipv8_rust_tunnels, RustError, PyException);

#[pyclass]
pub struct Endpoint {
    addr: String,
    socket: Option<Arc<UdpSocket>>,
    settings: Option<Arc<ArcSwap<TunnelSettings>>>,
    circuits: Arc<Mutex<HashMap<u32, Circuit>>>,
    relays: Arc<Mutex<HashMap<u32, RelayRoute>>>,
    exit_sockets: Arc<Mutex<HashMap<u32, ExitSocket>>>,
    udp_associates: Arc<Mutex<HashMap<u16, JoinHandle<()>>>>,
    tokio_shutdown: Option<Sender<()>>,
}

#[pymethods]
impl Endpoint {
    #[new]
    fn new(listen_addr: String, list_port: u16) -> Self {
        Endpoint {
            addr: format!("{}:{}", listen_addr, list_port),
            socket: None,
            settings: None,
            circuits: Arc::new(Mutex::new(HashMap::new())),
            relays: Arc::new(Mutex::new(HashMap::new())),
            exit_sockets: Arc::new(Mutex::new(HashMap::new())),
            udp_associates: Arc::new(Mutex::new(HashMap::new())),
            tokio_shutdown: None,
        }
    }

    fn open(&mut self, callback: PyObject, worker_threads: usize) -> PyResult<()> {
        if self.socket.is_some() {
            return Err(RustError::new_err("Endpoint.open was called behore"));
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
        self.settings = Some(settings.clone());

        info!("Spawning socket task");
        let addr = self.addr.clone();
        let circuits = self.circuits.clone();
        let relays = self.relays.clone();
        let exit_sockets = self.exit_sockets.clone();
        let (socket_tx, socket_rx) = std::sync::mpsc::channel();
        settings.load().handle.spawn(async move {
            let socket = Arc::new(UdpSocket::bind(addr).await.unwrap());
            socket_tx
                .send(socket.clone())
                .expect("Failed to send Tokio socket");
            info!("Tunnel socket listening on: {:?}", socket.local_addr().unwrap());

            let mut ts = TunnelSocket::new(socket, circuits, relays, exit_sockets, settings);
            ts.listen_forever().await;
        });
        self.socket = Some(socket_rx.recv().expect("Failed to get Tokio socket"));
        Ok(())
    }

    fn close(&mut self) -> PyResult<()> {
        info!("Shutting down rust endpoint");

        if let Some(shutdown) = self.tokio_shutdown.take() {
            if let Err(e) = shutdown.send(()) {
                error!("Unable to shutdown Tokio thread: {:?}", e);
            }
        }
        Ok(())
    }

    fn create_udp_associate(&mut self, port: u16, hops: u8) -> PyResult<u16> {
        if !self.is_open() {
            return Err(RustError::new_err("Endpoint is not open"));
        }

        let tunnel_socket = self.socket.clone().unwrap().clone();
        let circuits = self.circuits.clone();
        let settings = self.settings.clone().unwrap().clone();
        let (port_tx, port_rx) = std::sync::mpsc::channel();

        let task = settings.load().handle.spawn(async move {
            let socket = UdpSocket::bind(format!("127.0.0.1:{}", port)).await.unwrap();
            let port = socket.local_addr().unwrap().port();
            port_tx.send(port).expect("Failed to send SOCKS5 associate port");

            match socks5::handle_associate(Arc::new(socket), tunnel_socket, circuits, settings, hops)
                .await
            {
                Ok(()) => {}
                Err(e) => error!("Error while handling SOCKS5 connection: {}", e),
            };
        });
        let port = port_rx.recv().expect("Failed to get SOCKS5 associate port");
        self.udp_associates.lock().unwrap().insert(port, task);
        Ok(port)
    }

    fn close_udp_associate(&mut self, port: u16) -> PyResult<()> {
        let binding = self.udp_associates.lock().unwrap();
        let Some(handle) = binding.get(&port) else {
            error!("Could not find UDP associate for port {}", port);
            return Ok(());
        };
        handle.abort();
        info!("Closed UDP associate for port {}", port);
        Ok(())
    }

    fn set_prefix(&mut self, prefix: &PyBytes) -> PyResult<()> {
        if let Some(settings) = &self.settings {
            let mut new_settings = TunnelSettings::clone(&settings.load_full());
            new_settings.prefix = prefix.as_bytes().to_vec();
            info!("Set tunnel prefix: {:?}", new_settings.prefix);
            settings.swap(Arc::new(new_settings));
        } else {
            error!("Failed to set tunnel prefix");
        }
        Ok(())
    }

    fn set_max_relay_early(&mut self, max_relay_early: u8) -> PyResult<()> {
        if let Some(settings) = &self.settings {
            let mut new_settings = TunnelSettings::clone(&settings.load_full());
            new_settings.max_relay_early = max_relay_early;
            info!("Set maximum number of relay early cells: {}", new_settings.max_relay_early);
            settings.swap(Arc::new(new_settings));
        } else {
            error!("Failed to set maximum number of relay early cells");
        }
        Ok(())
    }

    fn set_peer_flags(&mut self, py_peer_flags: &PyAny) -> PyResult<()> {
        let mut peer_flags = HashSet::new();
        for py_peer_flag in py_peer_flags.downcast::<PySet>()? {
            peer_flags.insert(match py_peer_flag.extract::<u16>()? {
                1 => PeerFlag::Relay,
                2 => PeerFlag::ExitBt,
                4 => PeerFlag::ExitIpv8,
                8 => PeerFlag::SpeedTest,
                f => {
                    warn!("Skipping invalid peer flag: {}", f);
                    continue;
                }
            });
        }

        if let Some(settings) = &self.settings {
            let mut new_settings = TunnelSettings::clone(&settings.load_full());
            new_settings.peer_flags = peer_flags;
            info!("Set peer flags: {:?}", new_settings.peer_flags);
            settings.swap(Arc::new(new_settings));
        } else {
            error!("Failed to set peer flags");
        }
        Ok(())
    }

    fn set_exit_address(&mut self, exit_addr: String) -> PyResult<()> {
        if let Some(settings) = &self.settings {
            let mut new_settings = TunnelSettings::clone(&settings.load_full());
            new_settings.exit_addr = exit_addr;
            info!("Set exit address: {:?}", new_settings.exit_addr);
            settings.swap(Arc::new(new_settings));
        } else {
            error!("Failed to set exit address");
        }
        Ok(())
    }

    fn get_address(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        if let Some(socket) = &self.socket {
            let addr = socket.local_addr().unwrap();
            let ip = addr.ip().to_string().to_object(py);
            let port = addr.port().to_object(py);
            Ok(PyTuple::new(py, vec![ip, port]).to_object(py))
        } else {
            Err(RustError::new_err("Socket is not open"))
        }
    }

    fn get_byte_counters(&mut self) -> PyResult<PyObject> {
        let mut bytes_up = 0;
        let mut bytes_down = 0;
        for (_, circuit) in self.circuits.lock().unwrap().iter() {
            bytes_up += circuit.bytes_up;
            bytes_down += circuit.bytes_down;
        }
        for (_, relay) in self.relays.lock().unwrap().iter() {
            bytes_up += relay.bytes_up;
            bytes_down += relay.bytes_down;
        }
        for (_, exit) in self.exit_sockets.lock().unwrap().iter() {
            bytes_up += exit.bytes_up;
            bytes_down += exit.bytes_down;
        }
        Python::with_gil(|py| Ok(PyTuple::new(py, vec![bytes_up, bytes_down]).to_object(py)))
    }

    fn is_open(&mut self) -> bool {
        self.socket.is_some() && self.settings.is_some()
    }

    fn send(&mut self, address: &PyTuple, bytes: &PyBytes) -> PyResult<()> {
        let socket_addr = parse_address(address)?;
        let packet = bytes.as_bytes().to_vec();
        trace!("Sending packet with {} bytes to {}", packet.len(), socket_addr);
        self.send_to(packet, socket_addr)
    }

    fn send_cell(&mut self, address: &PyTuple, bytes: &PyBytes) -> PyResult<()> {
        let socket_addr = parse_address(address)?;
        let packet = bytes.as_bytes().to_vec();
        let guard = self.settings.clone().unwrap().load();

        if !payload::is_cell(&guard.prefix, &packet) {
            error!("Trying to send invalid cell");
            return Ok(());
        }

        let circuit_id = u32::from_be_bytes(packet[23..27].try_into().unwrap());
        debug!("Sending cell({}) for {} to {}", packet[29], circuit_id, socket_addr);

        if let Some(circuit) = self.circuits.lock().unwrap().get_mut(&circuit_id) {
            return Ok(match circuit.encrypt_outgoing_cell(packet, guard.max_relay_early) {
                Ok(cell) => self.send_to(cell, socket_addr)?,
                Err(e) => error!("Error while encrypting cell for circuit {}: {}", circuit_id, e),
            });
        }

        if let Some(exit) = self.exit_sockets.lock().unwrap().get_mut(&circuit_id) {
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

        let relay_circuit_id = match self.relays.lock().unwrap().get(&circuit_id) {
            #[rustfmt::skip]
            Some(relay) => if relay.rendezvous_relay { circuit_id } else { relay.circuit_id },
            None => return Ok(()),
        };
        if let Some(relay) = self.relays.lock().unwrap().get_mut(&relay_circuit_id) {
            return Ok(match relay.encrypt_outgoing_cell(packet) {
                Ok(cell) => self.send_to(cell, socket_addr)?,
                Err(e) => error!("Error while encrypting cell for relay {}: {}", circuit_id, e),
            });
        }
        warn!("Not sending cell to {}", socket_addr);
        Ok(())
    }

    fn add_circuit(&mut self, circuit_id: u32, py_circuit: PyObject) -> PyResult<()> {
        let mut circuit = Circuit::new(circuit_id);
        set_circuit_keys(&mut circuit, &py_circuit)?;
        self.circuits.lock().unwrap().insert(circuit.circuit_id, circuit);
        Ok(())
    }

    fn update_circuit(&mut self, circuit_id: u32, py_circuit: PyObject) -> PyResult<()> {
        if let Some(circuit) = self.circuits.lock().unwrap().get_mut(&circuit_id) {
            set_circuit_keys(circuit, &py_circuit)?;
            set_stats(circuit.bytes_up, circuit.bytes_down, circuit.last_activity, &py_circuit)?;
        }
        Ok(())
    }

    fn update_circuit_stats(&mut self, circuit_id: u32, py_circuit: PyObject) -> PyResult<()> {
        if let Some(circuit) = self.circuits.lock().unwrap().get_mut(&circuit_id) {
            set_stats(circuit.bytes_up, circuit.bytes_down, circuit.last_activity, &py_circuit)?;
        }
        Ok(())
    }

    fn remove_circuit(&mut self, circuit_id: u32) {
        self.circuits.lock().unwrap().remove(&circuit_id);
    }

    fn add_relay(&mut self, circuit_id: u32, py_relay: PyObject) -> PyResult<()> {
        Python::with_gil(|py| {
            let mut relay = RelayRoute::new(py_relay.getattr(py, "circuit_id")?.extract::<u32>(py)?);
            relay.direction = match py_relay.getattr(py, "direction")?.extract(py)? {
                0 => Direction::Forward,
                _ => Direction::Backward,
            };
            let hop = py_relay.getattr(py, "hop")?.into_ref(py);
            relay.peer = addr_from_hop(&hop)?;
            relay.keys.push(keys_from_hop(&hop)?);
            relay.rendezvous_relay = py_relay.getattr(py, "rendezvous_relay")?.extract::<bool>(py)?;
            self.relays.lock().unwrap().insert(circuit_id, relay);
            Ok(())
        })
    }

    fn update_relay_stats(&mut self, circuit_id: u32, py_relay: PyObject) -> PyResult<()> {
        if let Some(relay) = self.relays.lock().unwrap().get_mut(&circuit_id) {
            set_stats(relay.bytes_up, relay.bytes_down, relay.last_activity, &py_relay)?;
        }
        Ok(())
    }

    fn remove_relay(&mut self, circuit_id: u32) {
        self.relays.lock().unwrap().remove(&circuit_id);
    }

    fn add_exit(&mut self, circuit_id: u32, py_exit: PyObject) -> PyResult<()> {
        let mut exit = ExitSocket::new(circuit_id);

        Python::with_gil(|py| {
            let hop = py_exit.getattr(py, "hop")?.into_ref(py);
            exit.peer = addr_from_hop(&hop)?;
            exit.keys.push(keys_from_hop(&hop)?);
            self.exit_sockets.lock().unwrap().insert(exit.circuit_id, exit);
            Ok(())
        })
    }

    fn update_exit_stats(&mut self, circuit_id: u32, py_exit: PyObject) -> PyResult<()> {
        if let Some(exit) = self.exit_sockets.lock().unwrap().get_mut(&circuit_id) {
            set_stats(exit.bytes_up, exit.bytes_down, exit.last_activity, &py_exit)?;
            return Python::with_gil(|py| {
                py_exit.setattr(py, "enabled", exit.socket.is_some())?;
                Ok(())
            });
        }
        Ok(())
    }

    fn remove_exit(&mut self, circuit_id: u32) {
        let mut exit_lock = self.exit_sockets.lock().unwrap();
        if let Some(exit) = exit_lock.get(&circuit_id) {
            if let Some(handle) = &exit.handle {
                handle.abort();
                info!("Closed socket listen task for exit {}", exit.circuit_id);
            }
        }
        exit_lock.remove(&circuit_id);
    }
}

impl Endpoint {
    fn send_to(&self, packet: Vec<u8>, address: SocketAddr) -> PyResult<()> {
        let Some(socket) = &self.socket else {
            return Err(RustError::new_err("Socket is not open"));
        };

        match socket.try_send_to(&packet, address) {
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // The socket is busy, so we'll retry on the Tokio thread and await it.
                let Some(settings) = &self.settings else {
                    return Err(RustError::new_err("No settings available"));
                };
                let Some(cloned_socket) = self.socket.clone() else {
                    return Err(RustError::new_err("Socket is not open"));
                };

                settings.load().handle.spawn(async move {
                    match cloned_socket.send_to(&packet, address).await {
                        Ok(_) => {}
                        Err(e) => error!("Could not send packet to {}: {}", address, e.to_string()),
                    };
                });
            }
            Err(e) => error!("Could not send packet to {}: {}", address, e.to_string()),
        };
        Ok(())
    }
}

#[pymodule]
#[pyo3(name = "rust_endpoint")]
pub fn ipv8_rust_tunnels(py: Python, module: &PyModule) -> PyResult<()> {
    env_logger::init();
    module.add("RustError", py.get_type::<RustError>())?;
    module.add_class::<Endpoint>()?;
    Ok(())
}

fn set_circuit_keys(circuit: &mut Circuit, py_circuit: &PyObject) -> PyResult<()> {
    circuit.keys.clear();

    Python::with_gil(|py| {
        let hops = py_circuit.getattr(py, "_hops")?;
        let hops_list = hops.downcast::<PyList>(py)?;
        for hop in hops_list {
            circuit.keys.push(keys_from_hop(&hop)?);
        }
        if !hops_list.is_empty() {
            let hop = hops_list.get_item(0)?;
            circuit.peer = addr_from_hop(&hop)?;
        }

        let hs_keys = py_circuit.getattr(py, "hs_session_keys")?;
        if !hs_keys.is_none(py) {
            circuit.hs_keys = vec![create_session_keys(&hs_keys.as_ref(py))?];
        }
        circuit.goal_hops = py_circuit.getattr(py, "goal_hops")?.extract::<u8>(py)?;
        circuit.circuit_type = match py_circuit.getattr(py, "ctype")?.extract::<String>(py)?.as_str() {
            "IP_SEEDER" => CircuitType::IPSeeder,
            "RP_SEEDER" => CircuitType::RPSeeder,
            "RP_DOWNLOADER" => CircuitType::RPDownloader,
            _ => CircuitType::Data,
        };
        Ok(())
    })
}

fn addr_from_hop(hop: &PyAny) -> PyResult<SocketAddr> {
    let address = hop.getattr("peer")?.getattr("address")?;
    parse_address(address)
}

fn keys_from_hop(hop: &PyAny) -> PyResult<SessionKeys> {
    create_session_keys(hop.getattr("keys")?)
}

fn create_session_keys(keys: &PyAny) -> PyResult<SessionKeys> {
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

fn parse_address(address: &PyAny) -> PyResult<SocketAddr> {
    let ip = address.get_item(0)?.extract::<String>()?;
    let port = address.get_item(1)?.extract::<u16>()?;
    match ip.parse::<IpAddr>() {
        Ok(addr) => Ok(SocketAddr::new(addr, port)),
        _ => Err(RustError::new_err("Invalid address")),
    }
}
