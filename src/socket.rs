use arc_swap::{ArcSwap, ArcSwapAny};
use deku::DekuReader;
use map_macro::hash_set;
use pyo3::types::PyBytes;
use pyo3::{PyObject, Python};
use rand::RngCore;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;
use std::{net::SocketAddr, sync::Arc};
use tokio::io::ErrorKind;
use tokio::net::UdpSocket;
use tokio::runtime::Handle;
use tokio::time::timeout;

use crate::crypto::Direction;
use crate::packet::{
    decrypt_cell, encrypt_cell, has_prefix, has_prefixes, is_cell, swap_circuit_id, unwrap_cell,
};
use crate::payload::{
    self, Address, HTTPResponsePayload, Header, Raw, TestRequestPayload, TestResponsePayload, VarLenH,
};
use crate::routing::circuit::CircuitType;
use crate::routing::exit::{ExitSocket, PeerFlag};
use crate::routing::table::RoutingTable;
use crate::socks5::Socks5Server;
use crate::util::{send_tcp_request, Result};

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
    pub default_remotes: HashMap<u8, SocketAddr>,
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
            default_remotes: HashMap::new(),
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
            default_remotes: settings.default_remotes.clone(),
        }
    }
}

pub struct TunnelSocket {
    rt: RoutingTable,
    socks_servers: Arc<Mutex<HashMap<SocketAddr, Socks5Server>>>,
}

impl TunnelSocket {
    pub fn new(rt: RoutingTable, socks_servers: Arc<Mutex<HashMap<SocketAddr, Socks5Server>>>) -> Self {
        TunnelSocket { rt, socks_servers }
    }

    pub async fn listen_forever(&mut self) {
        let mut buf = [0; 2048];
        let listen_addr = self.rt.socket.local_addr().unwrap();

        loop {
            match self.rt.socket.recv_from(&mut buf).await {
                Ok((n, addr)) => {
                    let packet = &buf[..n];
                    self.rt.stats.lock().unwrap().add_down(packet, n);

                    let guard = ArcSwapAny::load(&self.rt.settings);

                    if !is_cell(&guard.prefix, &packet) {
                        if has_prefixes(&guard.prefixes, packet) {
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
        &mut self,
        packet: &[u8],
        addr: SocketAddr,
        circuit_id: u32,
    ) -> Result<usize> {
        let guard = ArcSwap::load(&self.rt.settings);
        let (data, cell_id, session_hops, to_python) =
            match self.rt.circuits.lock().unwrap().get_mut(&circuit_id) {
                Some(circuit) => {
                    let mut data = circuit.decrypt_incoming_cell(packet, guard.max_relay_early)?;
                    let session_hops = match circuit.circuit_type {
                        CircuitType::RPDownloader => circuit.goal_hops - 1,
                        CircuitType::RPSeeder => circuit.goal_hops,
                        _ => 0,
                    };
                    let cell_id = data[29];
                    let to_python = (data.len() > 52 && has_prefix(&guard.prefix, &data[30..]))
                        || (circuit.socket.is_none() && session_hops == 0);
                    if !to_python && cell_id == 1 {
                        data = circuit.process_incoming_cell(data)?
                    }
                    (data, cell_id, session_hops, to_python)
                }
                None => return Ok(0),
            };

        if to_python || cell_id != 1 {
            return self.on_incoming_packet(addr, circuit_id, &data).await;
        }

        let Some(socket) = self.get_socket_for_circuit(circuit_id) else {
            // It could be that we're getting incoming data from an e2e circuit and we don't have associated
            // the circuit with a socket yet (meaning that we haven't sent any traffic). If this is the case,
            // send the packet to all UDP associates with the correct hop count.
            if session_hops != 0 {
                for server in self.socks_servers.lock().unwrap().values() {
                    if server.hops != session_hops {
                        continue;
                    }

                    for associate in server.associates.lock().unwrap().values() {
                        if associate.socket.peer_addr().is_err() {
                            continue;
                        }

                        match associate.socket.try_send(&data) {
                            Ok(_) => trace!(
                                "Forwarding packet for circuit {} to associate socket {}",
                                circuit_id,
                                associate.socket.peer_addr().unwrap()
                            ),
                            Err(e) => error!("Error while sending e2e packet to SOCKS5: {}", e),
                        };
                    }
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
        let result = match self.rt.relays.lock().unwrap().get_mut(&circuit_id) {
            Some(relay) => {
                let target = relay.peer.clone();
                let cell = if relay.rendezvous_relay {
                    // We'll do hidden services after releasing the lock
                    packet.to_vec()
                } else {
                    trace!("Relaying cell from {} to {} ({})", circuit_id, relay.circuit_id, target);
                    relay.convert_incoming_cell(packet, self.rt.settings.load().max_relay_early)?
                };
                Some((target, cell, relay.rendezvous_relay))
            }
            None => None,
        };

        if let Some((target, mut data, hs)) = result {
            if hs {
                data = self.convert_hidden_services(packet, circuit_id)?;
            }
            return match self.rt.socket.send_to(&data, target).await {
                Ok(bytes) => {
                    self.rt.stats.lock().unwrap().add_up(&data, data.len());
                    Ok(bytes)
                }
                Err(e) => Err(format!("Failed to send data: {}", e)),
            };
        }
        Ok(0)
    }

    async fn handle_cell_for_exit(
        &mut self,
        packet: &[u8],
        addr: SocketAddr,
        circuit_id: u32,
    ) -> Result<usize> {
        let guard = ArcSwap::load(&self.rt.settings);
        let (data, cell_id, target, to_python) = match self.rt.exits.lock().unwrap().get_mut(&circuit_id)
        {
            Some(exit) => {
                let mut data = exit.decrypt_incoming_cell(packet, guard.max_relay_early)?;
                let mut target = match addr {
                    SocketAddr::V4(addr) => Address::V4(addr),
                    SocketAddr::V6(addr) => Address::V6(addr),
                };
                let cell_id = data[29];
                let to_python = data.len() > 52 && has_prefix(&guard.prefix, &data[30..]);
                if !to_python && cell_id == 1 {
                    (target, data) = exit.process_incoming_cell(data)?;
                }
                (data, cell_id, target, to_python)
            }
            None => return Ok(0),
        };

        ExitSocket::check_if_allowed(&data, &guard.prefix, &guard.peer_flags)?;
        if to_python || cell_id != 1 {
            return self.on_incoming_packet(addr, circuit_id, &data).await;
        }

        if let Some(socket) = self.get_socket_for_exit(circuit_id) {
            let resolved_target = self.resolve(target, circuit_id).await?;
            let ip = resolved_target.ip();
            // Use is_global, once it is available.
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                // For testing purposes, allow all IPs when bound to localhost.
                let local_addr = self.rt.socket.local_addr().unwrap();
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
        let (decrypted, next_circuit_id) = match self.rt.relays.lock().unwrap().get_mut(&circuit_id) {
            Some(relay) => (decrypt_cell(cell, Direction::Forward, &relay.keys)?, relay.circuit_id),
            None => return Err("Can't find first rendezvous relay".to_owned()),
        };

        let encrypted = match self.rt.relays.lock().unwrap().get_mut(&next_circuit_id) {
            Some(other) => encrypt_cell(&decrypted, Direction::Backward, &mut other.keys)?,
            None => return Err("Can't find rendezvous second relay".to_owned()),
        };

        info!("Forwarding packet for rendezvous {} -> {}", circuit_id, next_circuit_id);
        Ok(swap_circuit_id(&encrypted, next_circuit_id))
    }

    fn get_socket_for_circuit(&self, circuit_id: u32) -> Option<Arc<UdpSocket>> {
        match self.rt.circuits.lock().unwrap().get_mut(&circuit_id) {
            Some(circuit) => circuit.socket.clone(),
            None => None,
        }
    }

    fn get_socket_for_exit(&self, circuit_id: u32) -> Option<Arc<UdpSocket>> {
        match self.rt.exits.lock().unwrap().get_mut(&circuit_id) {
            Some(exit) => {
                if exit.socket.is_some() {
                    return exit.socket.clone();
                };

                let guard = self.rt.settings.load();
                exit.open_socket(guard.exit_addr.clone());
                let circuit_id = exit.circuit_id.clone();
                let rt = self.rt.clone();
                let task = guard.handle.spawn(async move {
                    match ExitSocket::listen_forever(circuit_id, rt).await {
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
            Address::DomainAddress((host, port)) => {
                let addr_string = format!("{}:{}", String::from_utf8_lossy(&*host), port);
                let Ok(addr_iter) = tokio::net::lookup_host(&addr_string).await else {
                    return Err(format!("Error while resolving address {}", addr_string));
                };
                let Some(addr) = addr_iter.last() else {
                    return Err(format!("Could not resolve address {}", addr_string));
                };

                info!("Resolved {} to {} for exit {}", addr_string, addr, circuit_id);
                Ok(addr)
            }
            Address::V4(addr) => Ok(SocketAddr::V4(addr)),
            Address::V6(addr) => Ok(SocketAddr::V6(addr)),
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

    async fn on_incoming_packet(
        &mut self,
        address: SocketAddr,
        circuit_id: u32,
        cell: &[u8],
    ) -> Result<usize> {
        let cell_id = cell[29];
        match cell_id {
            21 => self.on_test_request(address, circuit_id, &cell).await,
            22 => self.on_test_response(address, circuit_id, &cell).await,
            28 => self.on_http_request(address, circuit_id, &cell).await,
            29 => self.on_http_response(address, circuit_id, &cell).await,
            _ => {
                trace!("Handover cell({}) for circuit {} to Python", cell_id, circuit_id);
                let guard = ArcSwap::load(&self.rt.settings);
                self.call_python(&guard.callback, &address, &cell);
                Ok(cell.len())
            }
        }
    }

    async fn on_test_request(
        &self,
        _address: SocketAddr,
        circuit_id: u32,
        cell: &[u8],
    ) -> Result<usize> {
        debug!("Got test-request from circuit {}", circuit_id);
        let mut cursor = std::io::Cursor::new(unwrap_cell(&cell.to_vec()));
        let mut reader = deku::reader::Reader::new(&mut cursor);
        let request = match TestRequestPayload::from_reader_with_ctx(&mut reader, ()) {
            Ok(p) => p,
            Err(e) => return Err(format!("Error while decoding test request: {}", e)),
        };

        let mut random_data = vec![0; request.response_size.try_into().unwrap()];
        rand::rng().fill_bytes(&mut random_data);
        let response = TestResponsePayload {
            header: Header {
                prefix: request.header.prefix,
                msg_id: 22,
                circuit_id,
            },
            identifier: request.identifier,
            response: Raw { data: random_data },
        };

        match self.rt.send_cell(circuit_id, &response).await {
            Ok(bytes) => {
                debug!("Sending test-response over circuit {}", circuit_id);
                Ok(bytes)
            }
            Err(e) => return Err(format!("error sending test-response: {}", e)),
        }
    }

    async fn on_test_response(
        &self,
        _address: SocketAddr,
        circuit_id: u32,
        cell: &[u8],
    ) -> Result<usize> {
        debug!("Got test-response from circuit {}", circuit_id);
        let mut cursor = std::io::Cursor::new(unwrap_cell(&cell.to_vec()));
        let mut reader = deku::reader::Reader::new(&mut cursor);
        let payload = match TestResponsePayload::from_reader_with_ctx(&mut reader, ()) {
            Ok(p) => p,
            Err(e) => return Err(format!("error while decoding test response: {}", e)),
        };
        let _ = self
            .rt
            .settings
            .load()
            .test_channel
            .send((payload.identifier, cell.len()));
        Ok(cell.len())
    }

    async fn on_http_request(
        &self,
        _address: SocketAddr,
        circuit_id: u32,
        cell: &[u8],
    ) -> Result<usize> {
        debug!("Got http-request from circuit {}", circuit_id);
        if !self.rt.settings.load().peer_flags.contains(&PeerFlag::ExitHttp) {
            return Err(format!("dropping http-request, exiting HTTP is disabled"));
        }
        let mut cursor = std::io::Cursor::new(unwrap_cell(&cell.to_vec()));
        let mut reader = deku::reader::Reader::new(&mut cursor);
        let request = match payload::HTTPRequestPayload::from_reader_with_ctx(&mut reader, ()) {
            Ok(p) => p,
            Err(e) => return Err(format!("error while decoding http request: {}", e)),
        };

        let permit_result = match self.rt.exits.lock().unwrap().get_mut(&circuit_id) {
            Some(exit) => exit.http_requests.clone().try_acquire_owned(),
            None => return Err(format!("dropping http-request, unknown exit")),
        };
        let permit = match permit_result {
            Ok(permit) => permit,
            Err(_) => return Err(format!("dropping http-request, request limit reached")),
        };

        // Handling a HTTP request can take a while, so spawn a separate task.
        let rt = self.rt.clone();
        self.rt.settings.load().handle.spawn(async move {
            let Ok(result) =
                timeout(Duration::new(5, 0), send_tcp_request(&request.target, &request.request.data))
                    .await
            else {
                warn!("TCP stream timed out");
                return;
            };

            let (tcp_response, http_body) = match result {
                Ok(r) => r,
                Err(e) => {
                    warn!("TCP stream error: {}", e);
                    return;
                }
            };
            debug!("TCP response from {}: {}", request.target, String::from_utf8_lossy(&tcp_response));

            if !tcp_response.starts_with(b"HTTP/1.1 307") {
                if bdecode::bdecode(&http_body).is_err() {
                    warn!("HTTP response from {} is not bencoded", request.target);
                    return;
                };
                info!("HTTP response from {}", request.target);
            }

            let num_cells = u16::div_ceil(tcp_response.len() as u16, 1400);
            for (index, chunk) in tcp_response.to_vec().chunks(1400).enumerate() {
                let response = HTTPResponsePayload {
                    header: Header {
                        prefix: request.header.prefix.to_vec(),
                        msg_id: 29,
                        circuit_id,
                    },
                    identifier: request.identifier,
                    part: index as u16,
                    total: num_cells,
                    response: VarLenH {
                        data_len: chunk.len() as u16,
                        data: chunk.to_vec(),
                    },
                };

                match rt.send_cell(circuit_id, &response).await {
                    Ok(_) => debug!("Sending http-response ({}) over circuit {}", index + 1, circuit_id),
                    Err(e) => {
                        error!("Error sending http-response: {}", e);
                        return;
                    }
                };
            }
            // Ensure the permit gets moved into this task and dropped at the end.
            drop(permit);
        });
        Ok(cell.len())
    }

    async fn on_http_response(
        &mut self,
        _address: SocketAddr,
        circuit_id: u32,
        cell: &[u8],
    ) -> Result<usize> {
        debug!("Got http-response from circuit {}", circuit_id);
        let identifier = u32::from_be_bytes(cell[30..34].try_into().unwrap());
        match self.rt.request_cache.get("HTTPRequest".to_owned(), identifier) {
            Some(cache) => {
                if let Err(_) = cache.send(unwrap_cell(&cell.to_vec())).await {
                    return Err(format!("error handling http-response"));
                }
            }
            None => return Err(format!("unexpected http-response")),
        }
        Ok(cell.len())
    }
}
