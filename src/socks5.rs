use deku::DekuReader;
use rand::{seq::IteratorRandom, Rng};
use socks5_proto::Address as Socks5Address;
use socks5_server::{
    auth::NoAuth, connection::state::NeedAuthenticate, proto::Reply, Command, IncomingConnection, Server,
};
use std::{
    collections::HashMap,
    io::Cursor,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};

use crate::{
    packet::{as_data_cell, ip_to_circuit_id},
    payload::{self, Address},
    routing::{
        circuit::{Circuit, CircuitType},
        exit::PeerFlag,
        table::RoutingTable,
    },
    util,
};

#[derive(Debug, Clone)]
pub struct Socks5Server {
    pub rt: RoutingTable,
    pub hops: u8,
    pub associates: Arc<Mutex<HashMap<SocketAddr, UDPAssociate>>>,
    pub local_addr: Option<SocketAddr>,
}

impl Socks5Server {
    pub fn new(rt: RoutingTable, hops: u8) -> Self {
        Self {
            rt,
            hops,
            associates: Arc::new(Mutex::new(HashMap::new())),
            local_addr: None,
        }
    }

    pub async fn listen_forever(&mut self, listener: TcpListener) -> Result<(), String> {
        let server = Server::new(listener, Arc::new(NoAuth) as Arc<_>);
        self.local_addr = Some(server.local_addr().unwrap());

        while let Ok((conn, _)) = server.accept().await {
            info!("New connection to Socks5 server");
            // We're cloning this object and move it into a separate Tokio task.
            // All needed fields are in Arc<Mutex<>> anyway, so this should work.
            let mut this = self.clone();
            tokio::spawn(async move {
                match this.handle_connection(conn).await {
                    Ok(()) => {}
                    Err(e) => error!("Socks5 server error: {}", e),
                };
            });
        }
        Ok(())
    }

    async fn handle_connection(
        &mut self,
        conn: IncomingConnection<(), NeedAuthenticate>,
    ) -> Result<(), String> {
        let conn = match conn.authenticate().await {
            Ok((conn, _)) => conn,
            Err((e, mut conn)) => {
                let _ = conn.shutdown().await;
                return Err(format!("failed to authenticate: {}", e));
            }
        };

        match conn.wait().await {
            Ok(Command::Associate(associate, _)) => {
                info!("Socks5 server received ASSOCIATE request");

                let port = 0;
                let addr = format!("127.0.0.1:{}", port).parse().unwrap();
                let socket = match util::create_socket(addr) {
                    Ok(socket) => socket,
                    Err(e) => {
                        let replied = associate
                            .reply(Reply::GeneralFailure, Socks5Address::unspecified())
                            .await;
                        match replied {
                            Ok(mut conn) => {
                                let _ = conn.close().await;
                            }
                            Err((_, mut conn)) => {
                                let _ = conn.shutdown().await;
                            }
                        };
                        return Err(format!("failed to create associate socket: {}", e));
                    }
                };

                let local_addr = socket.local_addr().unwrap();
                let replied = associate
                    .reply(Reply::Succeeded, Socks5Address::SocketAddress(local_addr))
                    .await;
                let mut conn = match replied {
                    Ok(conn) => conn,
                    Err((e, mut conn)) => {
                        let _ = conn.shutdown().await;
                        return Err(format!("failed to reply to ASSOCIATE: {}", e));
                    }
                };

                let mut associate = UDPAssociate::new(self.rt.clone(), self.hops, socket);
                self.associates
                    .lock()
                    .unwrap()
                    .insert(local_addr, associate.clone());

                match associate.handle_associate().await {
                    Ok(()) => {}
                    Err(e) => error!("error while handling Socks5 connection: {}", e),
                };

                self.associates.lock().unwrap().remove(&local_addr);
                let _ = conn.close().await;
            }
            Ok(Command::Bind(bind, _)) => {
                info!("Socks5 server received BIND request");

                let replied = bind
                    .reply(Reply::CommandNotSupported, Socks5Address::unspecified())
                    .await;
                let mut conn = match replied {
                    Ok(conn) => conn,
                    Err((e, mut conn)) => {
                        let _ = conn.shutdown().await;
                        return Err(format!("failed to reply to BIND: {}", e));
                    }
                };

                let _ = conn.close().await;
            }
            Ok(Command::Connect(connect, socks5_address)) => {
                info!("Socks5 server received CONNECT for {}", socks5_address);

                let replied = connect
                    .reply(Reply::Succeeded, Socks5Address::unspecified())
                    .await;
                let mut conn = match replied {
                    Ok(conn) => conn,
                    Err((e, mut conn)) => {
                        let _ = conn.shutdown().await;
                        return Err(format!("failed to reply to CONNECT: {}", e));
                    }
                };

                let mut buffer = [0; 100 * 1024];
                let request_len = match conn.read(&mut buffer).await {
                    Ok(request_len) => request_len,
                    Err(e) => return Err(format!("failed to read HTTP request from connection {}", e)),
                };

                let address = match socks5_address {
                    Socks5Address::SocketAddress(SocketAddr::V4(addr)) => Address::V4(addr),
                    Socks5Address::SocketAddress(SocketAddr::V6(addr)) => Address::V6(addr),
                    Socks5Address::DomainAddress(host, port) => Address::DomainAddress((host, port)),
                };
                match self.perform_http_request(address, &buffer[..request_len]).await {
                    Ok(http_response) => {
                        let _ = conn.write(&http_response).await;
                    }
                    Err(e) => {
                        error!("Got error while performing HTTP request: {}", e);
                    }
                };

                let _ = conn.shutdown().await;
            }
            Err((e, mut conn)) => {
                let _ = conn.shutdown().await;
                return Err(e.to_string());
            }
        }

        Ok(())
    }

    async fn perform_http_request(
        &mut self,
        destination: Address,
        http_request: &[u8],
    ) -> Result<Vec<u8>, String> {
        // We need a circuit that supports HTTP requests, meaning that the circuit will have to end
        // with a node that has the PEER_FLAG_EXIT_HTTP flag set.
        let mut cid_available = None;
        for (_, c) in self.rt.circuits.lock().unwrap().iter() {
            if c.goal_hops == self.hops && c.data_ready() && c.exit_flags.contains(&PeerFlag::ExitHttp) {
                cid_available = Some(c.circuit_id);
                break;
            }
        }
        let Some(cid) = cid_available else {
            return Err("No HTTP circuit available".to_string());
        };
        debug!("Using circuit {} for HTTP request", cid);

        // Create and send the request.
        let identifier: u32 = rand::rng().random();
        let payload = payload::HTTPRequestPayload {
            header: payload::Header {
                prefix: self.rt.settings.load().prefix.clone(),
                msg_id: 28,
                circuit_id: cid,
            },
            identifier,
            target: destination.clone(),
            request: payload::VarLenH {
                data_len: http_request.len() as u16,
                data: http_request.to_vec(),
            },
        };

        match self.rt.send_cell(cid, &payload).await {
            Ok(_) => debug!("Sending http-request over circuit {}", cid),
            Err(e) => return Err(format!("error sending http-request: {}", e)),
        };

        // Wait for a response
        let prefix = "HTTPRequest".to_owned();
        let mut rx = self.rt.request_cache.add(prefix.clone(), identifier, 100);
        let Ok(result) = timeout(Duration::new(5, 0), async {
            let mut parts: HashMap<u16, Vec<u8>> = HashMap::new();
            loop {
                let Some(part) = rx.recv().await else {
                    return Err(format!("channel is closed for http-request {}:{}", prefix, identifier));
                };

                let mut cursor = std::io::Cursor::new(&part);
                let mut reader = deku::reader::Reader::new(&mut cursor);
                let payload = match payload::HTTPResponsePayload::from_reader_with_ctx(&mut reader, ()) {
                    Ok(p) => p,
                    Err(e) => return Err(format!("error decoding http-response: {}", e)),
                };

                debug!("Got http-response {} / {}", payload.part + 1, payload.total);
                parts.insert(payload.part, payload.response.data);
                if parts.len() == payload.total as usize {
                    break;
                }
            }

            let mut parts_vec: Vec<(u16, Vec<u8>)> = parts.into_iter().collect();
            parts_vec.sort_by_key(|r| r.0);
            Ok(parts_vec
                .iter()
                .map(|r| r.1.clone())
                .collect::<Vec<Vec<u8>>>()
                .concat())
        })
        .await
        else {
            self.rt.request_cache.pop(prefix.clone(), identifier);
            return Err(format!("http-request {}:{} timed out", prefix, identifier));
        };

        self.rt.request_cache.pop(prefix.clone(), identifier);
        let Ok(response) = result else {
            return Err(format!("error receiving http-response {}:{}", prefix, identifier));
        };

        debug!(
            "Got http-response for request {}:{}: {}",
            prefix,
            identifier,
            String::from_utf8_lossy(&response)
        );
        Ok(response)
    }
}

#[derive(Debug, Clone)]
pub struct UDPAssociate {
    pub rt: RoutingTable,
    pub hops: u8,
    pub socket: Arc<UdpSocket>,
    pub addr_to_cid: Arc<Mutex<HashMap<Address, u32>>>,
}

impl UDPAssociate {
    pub fn new(rt: RoutingTable, hops: u8, socket: Arc<UdpSocket>) -> Self {
        Self {
            rt,
            hops,
            socket,
            addr_to_cid: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn handle_associate(&mut self) -> Result<(), String> {
        let mut connected = false;
        let mut buf = [0; 2048];

        info!(
            "Listening on UDP associate socket {} ({} hops)",
            self.socket.local_addr().unwrap(),
            self.hops
        );

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((size, address)) => {
                    if !connected {
                        if let Err(e) = self.socket.connect(address).await {
                            return Err(format!("Error while calling socket.connect: {:?}", e));
                        };
                        connected = true;
                    }

                    let Some((target, cell, circuit_id)) =
                        self.process_socks5_packet(&buf[..size]).await
                    else {
                        continue;
                    };

                    match self.rt.socket.send_to(&cell, target).await {
                        Ok(_) => {
                            self.rt.stats.lock().unwrap().add_up(&cell, cell.len());
                            debug!("Forwarded data from SOCKS5 to circuit {}", circuit_id);
                        }
                        Err(_) => error!("Could not tunnel cell for circuit {}", circuit_id),
                    };
                }
                Err(e) => return Err(format!("Error while reading SOCK5 socket {:?}", e)),
            }
        }
    }

    async fn process_socks5_packet(&mut self, buf: &[u8]) -> Option<(SocketAddr, Vec<u8>, u32)> {
        let mut cursor = Cursor::new(buf);
        let mut reader = deku::reader::Reader::new(&mut cursor);
        let pkt = match payload::Socks5Payload::from_reader_with_ctx(&mut reader, ()) {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to decode SOCKS5 payload: {}", e);
                return None;
            }
        };

        let Some(circuit_id) = self.select_circuit(&pkt.dst) else {
            warn!("No {}-hop circuits available, dropping packet", self.hops);
            return None;
        };

        match self.rt.circuits.lock().unwrap().get_mut(&circuit_id) {
            Some(circuit) => {
                let guard = self.rt.settings.load();
                let max_relay_early = guard.max_relay_early;
                let prefix = &guard.prefix;
                let origin = Address::V4(SocketAddrV4::new(Ipv4Addr::from(0), 0));
                let cell = as_data_cell(prefix, circuit_id, &pkt.dst, &origin, &pkt.data.data);

                let Ok(encrypted_cell) = circuit.encrypt_outgoing_cell(cell, max_relay_early) else {
                    error!("Error while encrypting cell for circuit {:?}", circuit_id);
                    return None;
                };

                circuit.bytes_up += encrypted_cell.len() as u32;
                Some((circuit.peer.clone(), encrypted_cell, circuit_id))
            }
            None => return None,
        }
    }

    fn select_circuit(&mut self, address: &Address) -> Option<u32> {
        // Deal with hidden services
        if let Address::V4(addr) = address {
            if addr.port() == 1024 {
                let cid = ip_to_circuit_id(addr.ip());
                if let Some(circuit) = self.rt.circuits.lock().unwrap().get(&cid) {
                    if (circuit.circuit_type == CircuitType::RPDownloader
                        || circuit.circuit_type == CircuitType::RPSeeder)
                        && (circuit.keys.len() == circuit.goal_hops as usize)
                    {
                        return Some(cid);
                    }
                }
            }
        }

        let addr_guard = self.addr_to_cid.lock().unwrap();
        let cid = addr_guard.get(address).copied();
        drop(addr_guard);

        // Remove dead circuits from addr_to_cid
        if let Some(cid) = cid {
            if !self.rt.circuits.lock().unwrap().contains_key(&cid) {
                debug!("Not sending packet for {} over dead circuit {}, removing link", address, cid);
                self.addr_to_cid.lock().unwrap().remove(address);
            }
        }

        // Return the circuit_id that's assigned to this address, or return a random circuit_id (if available)
        match cid {
            Some(cid) => Some(cid),
            None => {
                let mut guard = self.rt.circuits.lock().unwrap();
                let mut options: Vec<&Circuit> = guard
                    .values()
                    .filter(|c| {
                        c.goal_hops == self.hops
                            && c.data_ready()
                            && (c.socket.is_none()
                                || Arc::ptr_eq(c.socket.as_ref().unwrap(), &self.socket))
                    })
                    .collect();
                options.sort_by_key(|c| c.socket.is_none() as u8);

                let Some(circuit_id) = options
                    .iter()
                    .take(2)
                    .map(|c| c.circuit_id)
                    .choose(&mut rand::rng())
                else {
                    return None;
                };

                if let Some(circuit) = guard.get_mut(&circuit_id) {
                    if circuit.socket.is_none() {
                        info!(
                            "Connecting circuit {} to associate socket {} ({} hops)",
                            circuit.circuit_id,
                            self.socket.local_addr().unwrap(),
                            self.hops
                        );
                        circuit.socket = Some(self.socket.clone());
                    }
                    self.addr_to_cid
                        .lock()
                        .unwrap()
                        .insert(address.clone(), circuit.circuit_id);
                    return Some(circuit.circuit_id);
                }
                None
            }
        }
    }
}
