use arc_swap::{ArcSwap, ArcSwapAny};
use map_macro::hash_set;
use pyo3::types::PyBytes;
use pyo3::{PyObject, Python};
use socks5_proto::Address;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::{net::SocketAddr, sync::Arc};
use tokio::io::ErrorKind;
use tokio::net::UdpSocket;
use tokio::runtime::Handle;

use crate::crypto::Direction;
use crate::payload;
use crate::routing::circuit::Circuit;
use crate::routing::exit::{ExitSocket, PeerFlag};
use crate::routing::relay::RelayRoute;
use crate::util::Result;

#[derive(Debug, Clone)]
pub struct TunnelSettings {
    pub prefix: Vec<u8>,
    pub max_relay_early: u8,
    pub peer_flags: HashSet<PeerFlag>,
    pub exit_addr: String,
    pub callback: PyObject,
    pub handle: Handle,
}

impl TunnelSettings {
    pub fn new(callback: PyObject, handle: Handle) -> Self {
        TunnelSettings {
            prefix: vec![0; 22],
            max_relay_early: 8,
            peer_flags: hash_set![PeerFlag::Relay, PeerFlag::SpeedTest],
            exit_addr: "[::]:0".to_owned(),
            callback,
            handle,
        }
    }
}

pub struct TunnelSocket {
    socket: Arc<UdpSocket>,
    circuits: Arc<Mutex<HashMap<u32, Circuit>>>,
    relays: Arc<Mutex<HashMap<u32, RelayRoute>>>,
    exit_sockets: Arc<Mutex<HashMap<u32, ExitSocket>>>,
    settings: Arc<ArcSwap<TunnelSettings>>,
}

impl TunnelSocket {
    pub fn new(
        socket: Arc<UdpSocket>,
        circuits: Arc<Mutex<HashMap<u32, Circuit>>>,
        relays: Arc<Mutex<HashMap<u32, RelayRoute>>>,
        exit_sockets: Arc<Mutex<HashMap<u32, ExitSocket>>>,
        settings: Arc<ArcSwap<TunnelSettings>>,
    ) -> Self {
        TunnelSocket {
            socket,
            circuits,
            relays,
            exit_sockets,
            settings,
        }
    }

    pub async fn listen_forever(&mut self) {
        let mut buf = [0; 2048];

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((n, addr)) => {
                    let packet = &buf[..n];
                    let guard = ArcSwapAny::load(&self.settings);

                    if !payload::is_cell(&guard.prefix, &packet) {
                        trace!("Handover packet with {} bytes from {} to Python", n, addr);
                        self.call_python(&guard.callback, &addr, packet);
                        continue;
                    }

                    let circuit_id = u32::from_be_bytes(packet[23..27].try_into().unwrap());
                    trace!("Got packet with circuit ID {} from {}", circuit_id, addr);

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

                    trace!("Dropping cell")
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
        let result = match self.circuits.lock().unwrap().get_mut(&circuit_id) {
            Some(circuit) => {
                let guard = ArcSwap::load(&self.settings);
                let cell = circuit.decrypt_incoming_cell(packet, guard.max_relay_early)?;
                if cell[29] != 1
                    || payload::has_prefix(&guard.prefix, &cell[30..])
                    || circuit.socket.is_none()
                {
                    Some((cell, true))
                } else {
                    Some((circuit.process_incoming_cell(cell)?, false))
                }
            }
            None => None,
        };

        if let Some((data, to_python)) = result {
            let guard = ArcSwap::load(&self.settings);
            if to_python {
                trace!("Handover cell({}) for circuit {} to Python", data[29], circuit_id);
                self.call_python(&guard.callback, &addr, &data);
                return Ok(data.len());
            }

            let Some(socket) = self.get_socket_for_circuit(circuit_id) else {
                // This shouldn't really happen, but we check anyway.
                return Err(format!("No socket available for exit {}", circuit_id));
            };
            return match socket.send(&data).await {
                Ok(bytes) => Ok(bytes),
                Err(e) => Err(format!("Failed to send data: {}", e)),
            };
        }
        Ok(0)
    }

    async fn handle_cell_for_relay(&self, packet: &[u8], circuit_id: u32) -> Result<usize> {
        let result = match self.relays.lock().unwrap().get_mut(&circuit_id) {
            Some(relay) => {
                let cell = if relay.rendezvous_relay {
                    // We'll do hidden services after releasing the lock
                    packet.to_vec()
                } else {
                    relay.convert_incoming_cell(packet, self.settings.load().max_relay_early)?
                };
                Some((relay.peer.clone(), cell, relay.rendezvous_relay))
            }
            None => None,
        };

        if let Some((target, mut data, hs)) = result {
            if hs {
                data = self.convert_hidden_services(packet, circuit_id)?;
            }
            return match self.socket.send_to(&data, target).await {
                Ok(bytes) => Ok(bytes),
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
        let result = match self.exit_sockets.lock().unwrap().get_mut(&circuit_id) {
            Some(exit) => {
                let guard = ArcSwap::load(&self.settings);
                let cell = exit.decrypt_incoming_cell(packet, guard.max_relay_early)?;
                if cell[29] != 1 || payload::has_prefix(&guard.prefix, &cell[30..]) {
                    Some((Address::SocketAddress(addr), cell, true))
                } else {
                    let (target, pkt) = exit.process_incoming_cell(cell)?;
                    Some((target, pkt, false))
                }
            }
            None => None,
        };

        if let Some((target, data, to_python)) = result {
            let guard = ArcSwap::load(&self.settings);
            ExitSocket::check_if_allowed(&data, &guard.prefix, &guard.peer_flags)?;
            if to_python {
                trace!("Handover cell({}) for exit {} to Python", data[29], circuit_id);
                self.call_python(&guard.callback, &addr, &data);
                return Ok(data.len());
            }

            if let Some(socket) = self.get_socket_for_exit(circuit_id) {
                let resolved_target = self.resolve(target, circuit_id).await?;
                return match socket.send_to(&data, resolved_target).await {
                    Ok(bytes) => Ok(bytes),
                    Err(e) => Err(format!("Failed to send data to {}: {}", resolved_target, e)),
                };
            }
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
                let exits = self.exit_sockets.clone();
                let settings = self.settings.clone();
                let task = guard.handle.spawn(async move {
                    match ExitSocket::listen_forever(socket, exits, circuit_id, settings).await {
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
}
