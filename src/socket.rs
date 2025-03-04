use arc_swap::{ArcSwap, ArcSwapAny};
use map_macro::hash_set;
use pyo3::types::PyBytes;
use pyo3::{PyObject, Python};
use rand::RngCore;
use socks5_proto::Address;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::{net::SocketAddr, sync::Arc};
use tokio::io::ErrorKind;
use tokio::net::UdpSocket;
use tokio::runtime::Handle;

use crate::crypto::Direction;
use crate::payload;
use crate::routing::circuit::{Circuit, CircuitType};
use crate::routing::exit::{ExitSocket, PeerFlag};
use crate::routing::relay::RelayRoute;
use crate::socks5::UDPAssociate;
use crate::stats::Stats;
use crate::util::Result;

#[derive(Debug)]
pub struct TunnelSettings {
    pub prefix: Vec<u8>,
    pub prefixes: Vec<Vec<u8>>,
    pub max_relay_early: u8,
    pub peer_flags: HashSet<PeerFlag>,
    pub exit_addr: SocketAddr,
    pub callback: PyObject,
    pub test_channel: tokio::sync::broadcast::Sender<(u32, usize)>,
    pub handle: Handle,
}

impl TunnelSettings {
    pub fn new(callback: PyObject, handle: Handle) -> Self {
        TunnelSettings {
            prefix: vec![0; 22],
            prefixes: vec![],
            max_relay_early: 8,
            peer_flags: hash_set![PeerFlag::Relay, PeerFlag::SpeedTest],
            exit_addr: "[::]:0".parse().unwrap(),
            callback,
            test_channel: tokio::sync::broadcast::Sender::<(u32, usize)>::new(200),
            handle,
        }
    }

    pub fn clone(settings: Arc<TunnelSettings>, py: Python<'_>) -> Self {
        TunnelSettings {
            prefix: settings.prefix.clone(),
            prefixes: settings.prefixes.clone(),
            max_relay_early: settings.max_relay_early.clone(),
            peer_flags: settings.peer_flags.clone(),
            exit_addr: settings.exit_addr.clone(),
            callback: settings.callback.clone_ref(py),
            test_channel: settings.test_channel.clone(),
            handle: settings.handle.clone(),
        }
    }
}

pub struct TunnelSocket {
    socket: Arc<UdpSocket>,
    stats: Arc<Mutex<Stats>>,
    circuits: Arc<Mutex<HashMap<u32, Circuit>>>,
    relays: Arc<Mutex<HashMap<u32, RelayRoute>>>,
    exit_sockets: Arc<Mutex<HashMap<u32, ExitSocket>>>,
    udp_associates: Arc<Mutex<HashMap<u16, UDPAssociate>>>,
    settings: Arc<ArcSwap<TunnelSettings>>,
}

impl TunnelSocket {
    pub fn new(
        socket: Arc<UdpSocket>,
        stats: Arc<Mutex<Stats>>,
        circuits: Arc<Mutex<HashMap<u32, Circuit>>>,
        relays: Arc<Mutex<HashMap<u32, RelayRoute>>>,
        exit_sockets: Arc<Mutex<HashMap<u32, ExitSocket>>>,
        udp_associates: Arc<Mutex<HashMap<u16, UDPAssociate>>>,
        settings: Arc<ArcSwap<TunnelSettings>>,
    ) -> Self {
        TunnelSocket {
            socket,
            stats,
            circuits,
            relays,
            exit_sockets,
            udp_associates,
            settings,
        }
    }

    pub async fn listen_forever(&mut self) {
        let mut buf = [0; 2048];
        let listen_addr = self.socket.local_addr().unwrap();

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((n, addr)) => {
                    let packet = &buf[..n];
                    self.stats.lock().unwrap().add_down(packet, n);

                    let guard = ArcSwapAny::load(&self.settings);

                    if !payload::is_cell(&guard.prefix, &packet) {
                        if payload::has_prefixes(&guard.prefixes, packet) {
                            trace!("Handover packet with {} bytes from {} to Python", n, addr);
                            self.call_python(&guard.callback, &addr, packet);
                        } else {
                            trace!("Dropping packet with {} bytes from {} (unknown prefix).", n, addr);
                        }
                        continue;
                    }

                    let circuit_id = u32::from_be_bytes(packet[23..27].try_into().unwrap());
                    trace!(
                        "Got packet with circuit ID {} from {}. Listening on {}",
                        circuit_id,
                        addr,
                        listen_addr
                    );

                    let mut result = self.handle_cell_for_circuit(packet, addr, circuit_id).await;
                    if Self::handle_result(result, format!("cell for circuit {}", circuit_id)) {
                        continue;
                    }
                    result = self.handle_cell_for_relay(packet, circuit_id).await;
                    if Self::handle_result(result, format!("cell for relay {}", circuit_id)) {
                        continue;
                    }
                    result = self.handle_cell_for_exit(packet, addr, circuit_id).await;
                    if Self::handle_result(result, format!("cell for exit {}", circuit_id)) {
                        continue;
                    }

                    if packet[27] != 0 {
                        debug!(
                            "Handover unencrypted cell({}) for with unknown circuit_id {} Python",
                            packet[29], circuit_id
                        );
                        self.call_python(&guard.callback, &addr, packet);
                        continue;
                    }

                    debug!("Dropping cell")
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    error!("Error while reading tunnel socket: {:?}", e);
                }
            }
        }
    }

    fn handle_result(result: Result<usize>, description: String) -> bool {
        if !result.as_ref().is_ok_and(|x| x == &0) {
            match result {
                Ok(_) => debug!("Processed {}", description),
                Err(e) => warn!("Error processing {}: {}", description, e),
            };
            return true;
        }
        false
    }

    async fn handle_cell_for_circuit(
        &self,
        packet: &[u8],
        addr: SocketAddr,
        circuit_id: u32,
    ) -> Result<usize> {
        let guard = ArcSwap::load(&self.settings);
        let (data, cell_id, session_hops, to_python) =
            match self.circuits.lock().unwrap().get_mut(&circuit_id) {
                Some(circuit) => {
                    let mut data = circuit.decrypt_incoming_cell(packet, guard.max_relay_early)?;
                    let session_hops = match circuit.circuit_type {
                        CircuitType::RPDownloader => circuit.goal_hops - 1,
                        CircuitType::RPSeeder => circuit.goal_hops,
                        _ => 0,
                    };
                    let cell_id = data[29];
                    let to_python = (data.len() > 52 && payload::has_prefix(&guard.prefix, &data[30..]))
                        || (circuit.socket.is_none() && session_hops == 0);
                    if !to_python && cell_id == 1 {
                        data = circuit.process_incoming_cell(data)?
                    }
                    (data, cell_id, session_hops, to_python)
                }
                None => return Ok(0),
            };

        if cell_id == 21 {
            return self.on_test_request(addr, circuit_id, &data).await;
        } else if cell_id == 22 {
            return self.on_test_response(addr, circuit_id, &data).await;
        } else if to_python || cell_id != 1 {
            trace!("Handover cell({}) for circuit {} to Python", cell_id, circuit_id);
            self.call_python(&guard.callback, &addr, &data);
            return Ok(data.len());
        }

        let Some(socket) = self.get_socket_for_circuit(circuit_id) else {
            // It could be that we're getting incoming data from an e2e circuit and we don't have associated
            // the circuit with a socket yet (meaning that we haven't sent any traffic). If this is the case,
            // send the packet to all UDP associates with the correct hop count.
            if session_hops != 0 {
                for associate in self.udp_associates.lock().unwrap().values() {
                    if associate.hops != session_hops || associate.default_remote.is_none() {
                        continue;
                    }
                    let default_remote = associate.default_remote.unwrap();
                    match associate.socket.try_send_to(&data, default_remote) {
                        Ok(_) => {}
                        Err(e) => error!("Error while sending e2e packet to SOCKS5: {}", e),
                    };
                }
                return Ok(data.len());
            }
            // This shouldn't really happen, but return an error anyway.
            return Err(format!("No socket available for circuit {}", circuit_id));
        };
        return match socket.send(&data).await {
            Ok(bytes) => Ok(bytes),
            Err(e) => Err(format!("Failed to send data: {}", e)),
        };
    }

    async fn handle_cell_for_relay(&self, packet: &[u8], circuit_id: u32) -> Result<usize> {
        let result = match self.relays.lock().unwrap().get_mut(&circuit_id) {
            Some(relay) => {
                let target = relay.peer.clone();
                let cell = if relay.rendezvous_relay {
                    // We'll do hidden services after releasing the lock
                    packet.to_vec()
                } else {
                    trace!("Relaying cell from {} to {} ({})", circuit_id, relay.circuit_id, target);
                    relay.convert_incoming_cell(packet, self.settings.load().max_relay_early)?
                };
                Some((target, cell, relay.rendezvous_relay))
            }
            None => None,
        };

        if let Some((target, mut data, hs)) = result {
            if hs {
                data = self.convert_hidden_services(packet, circuit_id)?;
            }
            return match self.socket.send_to(&data, target).await {
                Ok(bytes) => {
                    self.stats.lock().unwrap().add_up(&data, data.len());
                    Ok(bytes)
                }
                Err(e) => Err(format!("Failed to send data: {}", e)),
            };
        }
        Ok(0)
    }

    async fn handle_cell_for_exit(
        &self,
        packet: &[u8],
        addr: SocketAddr,
        circuit_id: u32,
    ) -> Result<usize> {
        let guard = ArcSwap::load(&self.settings);
        let (data, cell_id, target, to_python) =
            match self.exit_sockets.lock().unwrap().get_mut(&circuit_id) {
                Some(exit) => {
                    let mut data = exit.decrypt_incoming_cell(packet, guard.max_relay_early)?;
                    let mut target = Address::SocketAddress(addr);
                    let cell_id = data[29];
                    let to_python = data.len() > 52 && payload::has_prefix(&guard.prefix, &data[30..]);
                    if !to_python && cell_id == 1 {
                        (target, data) = exit.process_incoming_cell(data)?;
                    }
                    (data, cell_id, target, to_python)
                }
                None => return Ok(0),
            };

        ExitSocket::check_if_allowed(&data, &guard.prefix, &guard.peer_flags)?;
        if cell_id == 21 {
            return self.on_test_request(addr, circuit_id, &data).await;
        } else if to_python || cell_id != 1 {
            trace!("Handover cell({}) for exit {} to Python", data[29], circuit_id);
            self.call_python(&guard.callback, &addr, &data);
            return Ok(data.len());
        }

        if let Some(socket) = self.get_socket_for_exit(circuit_id) {
            let resolved_target = self.resolve(target, circuit_id).await?;
            let ip = resolved_target.ip();
            // Use is_global, once it is available.
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                // For testing purposes, allow all IPs when bound to localhost.
                let local_addr = self.socket.local_addr().unwrap();
                if !local_addr.ip().is_loopback() {
                    return Err(format!("Address {} is not allowed. Dropping packet.", ip));
                }
            }
            return match socket.send_to(&data, resolved_target).await {
                Ok(bytes) => Ok(bytes),
                Err(e) => Err(format!("Failed to send data to {}: {}", resolved_target, e)),
            };
        }
        Ok(0)
    }

    fn convert_hidden_services(&self, cell: &[u8], circuit_id: u32) -> Result<Vec<u8>> {
        let (decrypted, next_circuit_id) = match self.relays.lock().unwrap().get_mut(&circuit_id) {
            Some(relay) => {
                (payload::decrypt_cell(cell, Direction::Forward, &relay.keys)?, relay.circuit_id)
            }
            None => return Err("Can't find first rendezvous relay".to_owned()),
        };

        let encrypted = match self.relays.lock().unwrap().get_mut(&next_circuit_id) {
            Some(other) => payload::encrypt_cell(&decrypted, Direction::Backward, &mut other.keys)?,
            None => return Err("Can't find rendezvous second relay".to_owned()),
        };

        info!("Forwarding packet for rendezvous {} -> {}", circuit_id, next_circuit_id);
        Ok(payload::swap_circuit_id(&encrypted, next_circuit_id))
    }

    fn get_socket_for_circuit(&self, circuit_id: u32) -> Option<Arc<UdpSocket>> {
        match self.circuits.lock().unwrap().get_mut(&circuit_id) {
            Some(circuit) => circuit.socket.clone(),
            None => None,
        }
    }

    fn get_socket_for_exit(&self, circuit_id: u32) -> Option<Arc<UdpSocket>> {
        match self.exit_sockets.lock().unwrap().get_mut(&circuit_id) {
            Some(exit) => {
                if exit.socket.is_some() {
                    return exit.socket.clone();
                };

                let guard = self.settings.load();
                exit.open_socket(guard.exit_addr.clone());
                let circuit_id = exit.circuit_id.clone();
                let socket = self.socket.clone();
                let stats = self.stats.clone();
                let exits = self.exit_sockets.clone();
                let settings = self.settings.clone();
                let task = guard.handle.spawn(async move {
                    match ExitSocket::listen_forever(socket, stats, exits, circuit_id, settings).await {
                        Ok(_) => {}
                        Err(e) => error!("Error for exit {}: {}", circuit_id, e),
                    };
                });

                exit.handle = Some(task);
                exit.socket.clone()
            }
            None => None,
        }
    }

    async fn resolve(&self, address: Address, circuit_id: u32) -> Result<SocketAddr> {
        match address {
            Address::DomainAddress(hostname, port) => {
                let addr_string = format!("{}:{}", String::from_utf8_lossy(&*hostname), port);
                let Ok(addr_iter) = tokio::net::lookup_host(&addr_string).await else {
                    return Err(format!("Error while resolving address {}", addr_string));
                };
                let Some(addr) = addr_iter.last() else {
                    return Err(format!("Could not resolve address {}", addr_string));
                };

                info!("Resolved {} to {} for exit {}", addr_string, addr, circuit_id);
                Ok(addr)
            }
            Address::SocketAddress(addr) => Ok(addr),
        }
    }

    fn call_python(&self, callback: &PyObject, addr: &SocketAddr, packet: &[u8]) {
        Python::with_gil(|py| {
            let py_bytes = PyBytes::new(py, packet);
            match callback.call1(py, (addr.ip().to_string(), addr.port(), py_bytes)) {
                Ok(_) => {}
                Err(e) => error!("Could not call Python callback: {}", e),
            }
        });
    }

    async fn on_test_request(&self, address: SocketAddr, circuit_id: u32, cell: &[u8]) -> Result<usize> {
        if cell.len() < 37 {
            return Err(format!("Got bad test-request from circuit {}", circuit_id));
        }
        debug!("Got test-request from circuit {}", circuit_id);
        let identifier = u32::from_be_bytes(cell[30..34].try_into().unwrap());
        let response_size = u16::from_be_bytes(cell[34..36].try_into().unwrap());
        let mut random_data = [0; 2048];
        rand::rng().fill_bytes(&mut random_data);

        let response = [
            cell[..22].to_vec(),
            vec![0],
            circuit_id.to_be_bytes().to_vec(),
            vec![0, 0, 22],
            identifier.to_be_bytes().to_vec(),
            random_data[..response_size as usize].to_vec(),
        ]
        .concat();

        let encrypted_cell = match self.exit_sockets.lock().unwrap().get_mut(&circuit_id) {
            Some(exit) => match exit.encrypt_outgoing_cell(response) {
                Ok(cell) => cell,
                Err(_) => return Err(format!("Failed to encrypt test-response for {:?}", circuit_id)),
            },
            None => match self.circuits.lock().unwrap().get_mut(&circuit_id) {
                Some(circuit) => {
                    match circuit.encrypt_outgoing_cell(response, self.settings.load().max_relay_early) {
                        Ok(cell) => cell,
                        Err(_) => {
                            return Err(format!("Failed to encrypt test-response for {:?}", circuit_id))
                        }
                    }
                }
                None => return Err(format!("Unexpected test-response for {:?}", circuit_id)),
            },
        };

        return match self.socket.send_to(&encrypted_cell, address).await {
            Ok(bytes) => {
                self.stats
                    .lock()
                    .unwrap()
                    .add_up(&encrypted_cell, encrypted_cell.len());
                Ok(bytes)
            }
            Err(e) => Err(format!("Failed to send test-response: {}", e)),
        };
    }

    async fn on_test_response(
        &self,
        _address: SocketAddr,
        circuit_id: u32,
        cell: &[u8],
    ) -> Result<usize> {
        if cell.len() < 35 {
            return Err(format!("Got bad test-response from circuit {}", circuit_id));
        }
        debug!("Got test-response from circuit {}", circuit_id);
        let tid = u32::from_be_bytes(cell[30..34].try_into().unwrap());
        let _ = self.settings.load().test_channel.send((tid, cell.len()));
        Ok(cell.len())
    }
}
