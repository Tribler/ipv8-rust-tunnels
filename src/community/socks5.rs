use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use deku::DekuContainerRead;
use rand::seq::IteratorRandom;
use rand::RngExt;
use socks5_proto::Address as Socks5Address;
use socks5_server::auth::NoAuth;
use socks5_server::connection::state::NeedAuthenticate;
use socks5_server::proto::Reply;
use socks5_server::{Command, IncomingConnection, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

use crate::community::routing::circuit::{Circuit, CircuitState, CircuitType};
use crate::community::routing::peer::PeerFlag;
use crate::community::routing::table::RoutingTable;
use crate::community::serialization::{ip_to_circuit_id, CellPayload};
use crate::community::serialization::{
    Address, HTTPRequestPayload, HTTPResponsePayload, Socks5Payload, VarLenH,
};
use crate::request_cache::RequestCache;
use crate::transport::buffer::Buffer;
use crate::util;

#[derive(Clone)]
pub struct Socks5Server {
    pub rt: RoutingTable,
    pub request_cache: RequestCache,
    pub hops: u8,
    pub associates: Arc<Mutex<HashMap<SocketAddr, UDPAssociate>>>,
    pub local_addr: Option<SocketAddr>,
}

impl Socks5Server {
    pub fn new(rt: RoutingTable, request_cache: RequestCache, hops: u8) -> Self {
        Self { rt, request_cache, hops, associates: Arc::new(Mutex::new(HashMap::new())), local_addr: None }
    }

    pub async fn listen_forever(&mut self, listener: TcpListener) -> Result<(), String> {
        let server = Server::new(listener, Arc::new(NoAuth) as Arc<_>);
        self.local_addr = Some(server.local_addr().unwrap());

        while let Ok((conn, _)) = server.accept().await {
            info!("New connection to Socks5 server");
            // We're cloning this object and move it into a separate Tokio task.
            // All needed fields are in Arc<Mutex<>> anyway, so this should work.
            let mut this = self.clone();
            self.rt.task_manager.spawn("socks5_connection", async move {
                match this.handle_connection(conn).await {
                    Ok(()) => {}
                    Err(e) => error!("Socks5 server error: {}", e),
                };
            });
        }
        Ok(())
    }

    pub async fn handle_connection(
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
                        let replied =
                            associate.reply(Reply::GeneralFailure, Socks5Address::unspecified()).await;
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
                let replied =
                    associate.reply(Reply::Succeeded, Socks5Address::SocketAddress(local_addr)).await;
                let mut conn = match replied {
                    Ok(conn) => conn,
                    Err((e, mut conn)) => {
                        let _ = conn.shutdown().await;
                        return Err(format!("failed to reply to ASSOCIATE: {}", e));
                    }
                };

                let mut associate = UDPAssociate::new(self.rt.clone(), self.hops, socket);
                self.associates.lock().unwrap().insert(local_addr, associate.clone());

                match associate.handle_associate().await {
                    Ok(()) => {}
                    Err(e) => error!("error while handling Socks5 connection: {}", e),
                };

                self.associates.lock().unwrap().remove(&local_addr);
                let _ = conn.close().await;
            }
            Ok(Command::Bind(bind, _)) => {
                info!("Socks5 server received BIND request");

                let replied = bind.reply(Reply::CommandNotSupported, Socks5Address::unspecified()).await;
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

                let replied = connect.reply(Reply::Succeeded, Socks5Address::unspecified()).await;
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
                    Socks5Address::DomainAddress(host, port) => {
                        Address::DomainAddress(VarLenH { data_len: host.len() as u16, data: host }, port)
                    }
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

    pub async fn perform_http_request(
        &mut self,
        destination: Address,
        http_request: &[u8],
    ) -> Result<Vec<u8>, String> {
        // We need a circuit that supports HTTP requests, meaning that the circuit will have to end
        // with a node that has the PEER_FLAG_EXIT_HTTP flag set.
        let mut cid_available = None;
        for (_, c) in self.rt.circuits.load().iter() {
            if c.goal_hops == self.hops && c.data_ready() && c.has_exit_flag(&PeerFlag::ExitHttp) {
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
        let payload = HTTPRequestPayload {
            circuit_id: cid,
            identifier,
            target: destination.clone(),
            request: VarLenH { data_len: http_request.len() as u16, data: http_request.to_vec() },
        };

        match self.rt.send_cell(&payload, None).await {
            Ok(_) => debug!("Sending http-request over circuit {}", cid),
            Err(e) => return Err(format!("error sending http-request: {}", e)),
        };

        // Wait for a response
        let prefix = "HTTPRequest".to_owned();
        let (mut rx, _guard) = self.request_cache.add(prefix.clone(), identifier, 100);
        let result = timeout(Duration::new(5, 0), async {
            let mut parts: HashMap<u16, Vec<u8>> = HashMap::new();
            loop {
                let Some(part) = rx.recv().await else {
                    return Err(format!("channel is closed for http-request {}:{}", prefix, identifier));
                };

                let (_, payload) = match HTTPResponsePayload::from_bytes((&part, 0)) {
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
            Ok(parts_vec.iter().map(|r| r.1.clone()).collect::<Vec<Vec<u8>>>().concat())
        })
        .await;

        let Ok(result) = result else {
            return Err(format!("http-request {}:{} timed out", prefix, identifier));
        };

        let response =
            result.map_err(|e| format!("error receiving http-response {}:{}: {}", prefix, identifier, e))?;

        debug!(
            "Got http-response for request {}:{}: {}",
            prefix,
            identifier,
            String::from_utf8_lossy(&response)
        );
        Ok(response)
    }
}

#[derive(Clone)]
pub struct UDPAssociate {
    pub rt: RoutingTable,
    pub hops: u8,
    pub socket: Arc<UdpSocket>,
    pub addr_to_cid: Arc<Mutex<HashMap<Address, u32>>>,
}

impl UDPAssociate {
    pub fn new(rt: RoutingTable, hops: u8, socket: Arc<UdpSocket>) -> Self {
        Self { rt, hops, socket, addr_to_cid: Arc::new(Mutex::new(HashMap::new())) }
    }

    pub async fn handle_associate(&mut self) -> Result<(), String> {
        let mut connected = false;
        let mut buf = [0; 2048];

        info!("Listening on UDP associate socket {} ({} hops)", self.socket.local_addr().unwrap(), self.hops);

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((size, address)) => {
                    if !connected {
                        if let Err(e) = self.socket.connect(address).await {
                            return Err(format!("Error while calling socket.connect: {:?}", e));
                        };
                        connected = true;
                    }

                    let Some((target, buffer, circuit_id)) = self.process_socks5_packet(&buf[..size]).await
                    else {
                        continue;
                    };

                    match self.rt.send_packet(target, buffer).await {
                        Ok(_) => {
                            debug!("Forwarded data from SOCKS5 to circuit {}", circuit_id);
                        }
                        Err(_) => error!("Could not tunnel cell for circuit {}", circuit_id),
                    };
                }
                Err(e) => return Err(format!("Error while reading SOCK5 socket {:?}", e)),
            }
        }
    }

    pub async fn process_socks5_packet(&self, buf: &[u8]) -> Option<(SocketAddr, Buffer, u32)> {
        let (_, pkt) = match Socks5Payload::from_bytes((buf, 0)) {
            Ok(res) => res,
            Err(e) => {
                error!("Failed to decode SOCKS5 payload zero-copy: {}", e);
                return None;
            }
        };

        let Some(circuit_id) = self.select_circuit(&pkt.dst) else {
            warn!("No {}-hop circuits available, dropping packet", self.hops);
            return None;
        };

        match self.rt.circuits.load().get(&circuit_id) {
            Some(circuit) => {
                let origin = Address::V4(SocketAddrV4::new(Ipv4Addr::from(0), 0));

                let mut buffer = match self.rt.outbound_pool.pull().await {
                    Ok(b) => b,
                    Err(e) => {
                        error!("SOCKS5 worker failed to acquire buffer: {}", e);
                        return None;
                    }
                };
                let raw_buf = buffer.inner.as_mut().unwrap();

                let mut cell =
                    match CellPayload::from_data(circuit_id, &pkt.dst, &origin, &pkt.data.data, raw_buf) {
                        Ok(c) => c,
                        Err(e) => {
                            error!("Error creating data cell for circuit {circuit_id}: {e}");
                            return None;
                        }
                    };

                if let Err(e) = circuit.add_all_layers(&mut cell) {
                    error!("Error encrypting data cell layers for circuit {circuit_id}: {e}");
                    return None;
                }

                let _ = circuit.process(&mut cell, false);
                Some((circuit.peer.clone(), buffer, circuit_id))
            }
            None => return None,
        }
    }

    pub fn select_circuit(&self, address: &Address) -> Option<u32> {
        let circuits_guard = self.rt.circuits.load();

        // Deal with hidden services
        if let Address::V4(addr) = address {
            if addr.port() == 1024 {
                let cid = ip_to_circuit_id(addr.ip());
                if let Some(circuit) = circuits_guard.get(&cid) {
                    if (circuit.circuit_type == CircuitType::RPDownloader
                        || circuit.circuit_type == CircuitType::RPSeeder)
                        && circuit.state() == CircuitState::Ready
                    {
                        return Some(cid);
                    }
                }
            }
        }

        let cid = {
            let mut addr_lock = self.addr_to_cid.lock().unwrap();
            let mut found_cid = addr_lock.get(address).copied();

            // Remove dead circuits from addr_to_cid
            if let Some(c) = found_cid {
                if !circuits_guard.contains_key(&c) {
                    debug!("Not sending packet for {} over dead circuit {}, removing link", address, c);
                    addr_lock.remove(address);
                    found_cid = None;
                }
            }

            found_cid
        };

        if let Some(c) = cid {
            // Return the circuit_id that's assigned to this address
            return Some(c);
        }

        // Return a random circuit_id (if available)
        let mut options: Vec<(&Arc<Circuit>, bool)> = circuits_guard
            .values()
            .filter(|c| c.goal_hops == self.hops && c.data_ready())
            .filter_map(|c| {
                let guard = c.socket.load();
                if guard.as_ref().is_none() {
                    Some((c, true))
                } else if Arc::ptr_eq(guard.as_ref().unwrap(), &self.socket) {
                    Some((c, false))
                } else {
                    None
                }
            })
            .collect();

        options.sort_by_key(|&(_, is_empty)| is_empty);

        let Some(&(circuit, is_empty)) = options.iter().take(2).choose(&mut rand::rng()) else {
            return None;
        };

        let circuit_id = circuit.circuit_id;

        if is_empty {
            circuit.socket.rcu(|old_socket| {
                if old_socket.is_none() {
                    Some(Arc::clone(&self.socket))
                } else {
                    Option::<Arc<UdpSocket>>::clone(old_socket)
                }
            });

            info!(
                "Connected circuit {} to associate socket {} ({} hops)",
                circuit_id,
                self.socket.local_addr().unwrap(),
                self.hops
            );
        }

        self.addr_to_cid.lock().unwrap().insert(address.clone(), circuit_id);

        Some(circuit_id)
    }
}
