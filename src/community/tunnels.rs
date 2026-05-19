use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwap;
use socks5_proto::UdpHeader;

use crate::community::hiddenservices::HiddenServiceState;
use crate::community::routing::circuit::CircuitType;
use crate::community::routing::peer::PeerCache;
use crate::community::routing::table::{RoutingTable, RoutingTarget};
use crate::community::serialization::{
    circuit_id_to_ip, unpack_data, CellId, CellPayload, ProtocolDomain, ALLOWED_CELLS_BW, ALLOWED_CELLS_FW,
    NO_CRYPTO_PACKETS,
};
use crate::community::serialization::{Address, MessageId};
use crate::community::socks5::Socks5Server;
use crate::request_cache::RequestCache;
use crate::transport::buffer::Buffer;
use crate::util::Result;

#[derive(Clone)]
pub struct TunnelCommunity {
    pub prefix: [u8; 22],
    pub rt: RoutingTable,
    pub request_cache: RequestCache,
    pub peer_cache: PeerCache,
    pub self_handle: OnceLock<Arc<TunnelCommunity>>,
    pub socks_servers: Arc<ArcSwap<HashMap<SocketAddr, Socks5Server>>>,
    pub local_addr: SocketAddr,
    pub hs_state: Arc<HiddenServiceState>,
}

impl TunnelCommunity {
    pub async fn on_packet(&self, src_addr: SocketAddr, mut buffer: Buffer) -> crate::util::Result<()> {
        let buf = buffer.inner.as_mut().unwrap();

        if buf.len() < 23 {
            return Ok(());
        }

        let msg_id = match MessageId::try_from(buf[22]) {
            Ok(id) => id,
            Err(_) => return Ok(()),
        };

        // Remove the outer layer (prefix)
        buf.drain(0..22);

        match msg_id {
            MessageId::Cell => self.on_cell(src_addr, buffer).await?,
            _ => self.on_message(src_addr, msg_id, buf).await?,
        }
        Ok(())
    }

    pub async fn on_cell(&self, src_addr: SocketAddr, mut buffer: Buffer) -> Result<()> {
        let buf = buffer.inner.as_mut().unwrap();

        let mut cell = CellPayload::from_packet(buf).map_err(|e| e.to_string())?;
        let circuit_id = cell.circuit_id();

        trace!(
            "Got cell ({} bytes) from {} (cid={}, local_addr={})",
            cell.buffer.len(),
            src_addr,
            circuit_id,
            self.local_addr
        );

        let cell_id_byte = cell.cell_id();
        let routing_object = self.rt.get_routing_object(circuit_id);

        if routing_object.is_none() && !NO_CRYPTO_PACKETS.contains(&cell_id_byte) {
            debug!("Dropping cell: unauthenticated");
            return Ok(());
        }
        if cell.is_plaintext() && !NO_CRYPTO_PACKETS.contains(&cell_id_byte) {
            return Err("Dropping cell: plaintext flag not allowed".to_owned());
        }

        if let Some(target) = routing_object {
            match &target {
                RoutingTarget::Relay(r) => {
                    r.apply_layer(&mut cell, true, circuit_id)?;
                    let next_hop = r.process(&mut cell, true, circuit_id)?.unwrap();
                    debug!("Relay {circuit_id} -> {}", cell.circuit_id());
                    self.rt.send_packet(next_hop, buffer).await?;
                    return Ok(());
                }
                RoutingTarget::Rendezvous(rv) => {
                    rv.remove_layer(&mut cell, circuit_id)?;
                    rv.add_layer(&mut cell, circuit_id)?;
                    let next_hop = rv.process(&mut cell, true, circuit_id)?.unwrap();
                    debug!("Rendezvous {circuit_id} -> {}", cell.circuit_id(),);
                    self.rt.send_packet(next_hop, buffer).await?;
                    return Ok(());
                }
                RoutingTarget::Circuit(c) => {
                    c.remove_all_layers(&mut cell)?;
                    c.process(&mut cell, true)?;
                    debug!("Circuit {} received cell (id={})", circuit_id, cell.cell_id());
                    if !ALLOWED_CELLS_BW.contains(&cell.cell_id()) {
                        return Err("Dropping cell: not allowed to go backwards".to_owned());
                    }
                }
                RoutingTarget::Exit(e) => {
                    e.remove_layer(&mut cell)?;
                    e.process(&mut cell, true)?;
                    debug!("Exit {} received cell (id={})", circuit_id, cell.cell_id());
                    if !ALLOWED_CELLS_FW.contains(&cell.cell_id()) {
                        return Err("Dropping cell: not allowed to go forwards".to_owned());
                    }
                }
            }
        }

        let cell_id = CellId::try_from(cell.cell_id()).map_err(|e| e)?;
        let inner = cell.unwrap();
        match cell_id.domain() {
            ProtocolDomain::Core => self.on_cell_core(src_addr, circuit_id, cell_id, inner).await?,
            ProtocolDomain::DataStream => self.on_data(src_addr, circuit_id, inner).await?,
            ProtocolDomain::HiddenServices => self.on_cell_hs(src_addr, circuit_id, cell_id, inner).await?,
        }

        Ok(())
    }

    pub async fn on_message(
        &self,
        src_addr: SocketAddr,
        msg_id: MessageId,
        buffer: &mut Vec<u8>,
    ) -> Result<()> {
        match msg_id.domain() {
            ProtocolDomain::Core => {
                self.on_message_core(src_addr, msg_id, buffer).await?;
            }
            ProtocolDomain::HiddenServices => {
                self.on_message_hs(src_addr, msg_id, buffer).await?;
            }
            ProtocolDomain::DataStream => {}
        }

        Ok(())
    }

    pub async fn on_data(&self, src_addr: SocketAddr, circuit_id: u32, data: &mut Vec<u8>) -> Result<()> {
        trace!("Got data cell from {} (cid={}, local_addr={})", src_addr, circuit_id, self.local_addr);

        let Some((target, origin, _)) = unpack_data(data) else {
            return Err("Failed to unpack data cell".to_owned());
        };

        let settings_guard = self.rt.settings.load();

        if self.rt.exits.load().contains_key(&circuit_id) {
            let exits = self.rt.exits.load();
            let exit = exits.get(&circuit_id).ok_or_else(|| format!("Cannot find exit {}", circuit_id))?;

            if exit.is_introduction.load(Ordering::Relaxed) || exit.is_rendezvous.load(Ordering::Relaxed) {
                return Err(format!("Dropping data for {circuit_id}: circuit is in-use be hidden services"));
            }

            let resolved_target = self.resolve(target, circuit_id).await?;
            let ip = resolved_target.ip();

            // Use is_global, once it is available.
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                // For testing purposes, allow all IPs when bound to localhost.
                if !self.local_addr.ip().is_loopback() {
                    return Err(format!("Address {} is restricted. Dropping packet.", ip));
                }
            }

            let socket = exit
                .socket
                .get()
                .unwrap_or_else(|| exit.create_socket(self.rt.clone(), settings_guard.exit_addr).unwrap());

            if let Err(e) = socket.send_to(&data, resolved_target).await {
                match e.kind() {
                    std::io::ErrorKind::NetworkUnreachable
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::TimedOut => {
                        debug!("Failed to send data to {resolved_target} (OS Error {:?})", e.raw_os_error());
                    }
                    std::io::ErrorKind::WouldBlock => {
                        warn!("Socket blocked while sending to {resolved_target}")
                    }
                    _ => return Err(format!("Failed to send data to {resolved_target}: {e}")),
                }
            }

            return Ok(());
        }

        let circuit_guard = self.rt.circuits.load();
        let circuit =
            circuit_guard.get(&circuit_id).ok_or_else(|| format!("Cannot find circuit {}", circuit_id))?;

        let mut org_addr = match &origin {
            Address::V4(addr) => socks5_proto::Address::SocketAddress(SocketAddr::V4(*addr)),
            Address::V6(addr) => socks5_proto::Address::SocketAddress(SocketAddr::V6(*addr)),
            Address::DomainAddress(var_len, port) => {
                let host_str = String::from_utf8_lossy(&var_len.data).into_owned();
                socks5_proto::Address::DomainAddress(host_str.into(), *port)
            }
        };

        if circuit.circuit_type == CircuitType::RPDownloader || circuit.circuit_type == CircuitType::RPSeeder
        {
            let ip = circuit_id_to_ip(circuit.circuit_id);
            org_addr = socks5_proto::Address::SocketAddress(SocketAddr::from((ip, 1024)));
        }

        let header = UdpHeader { frag: 0, address: org_addr };
        let header_len = header.serialized_len();
        let data_len = data.len();

        data.resize(header_len + data_len, 0);
        data.copy_within(0..data_len, header_len);

        let mut header_slice = &mut data[..header_len];
        header.write_to_buf(&mut header_slice);

        debug!("Sending packet from circuit {} to SOCKS5 server", circuit.circuit_id);

        let socket_opt = circuit.socket.load().as_ref().map(Arc::clone);
        if let Some(socket) = socket_opt {
            socket
                .send(data)
                .await
                .map_err(|e| format!("SOCKS5 socket streaming error on circuit {circuit_id}: {e}"))?;
            return Ok(());
        }

        let hops = match circuit.circuit_type {
            CircuitType::RPDownloader => circuit.goal_hops - 1,
            CircuitType::RPSeeder => circuit.goal_hops,
            _ => 0,
        };

        if hops != 0 {
            // It could be that we're getting incoming data from an e2e circuit and we don't have associated
            // the circuit with a socket yet (meaning that we haven't sent any traffic). If this is the case,
            // send the packet to all UDP associates with the correct hop count.
            let servers = self.socks_servers.load();
            for server in servers.values().filter(|s| s.hops == hops) {
                let associates = server.associates.lock().unwrap();
                for associate in associates.values().filter(|a| a.socket.peer_addr().is_ok()) {
                    let _ = associate.socket.try_send(data);
                }
            }
            return Ok(());
        }

        warn!("Nothing to do with data for circuit {}", circuit_id);
        Ok(())
    }

    async fn resolve(&self, address: Address, circuit_id: u32) -> Result<SocketAddr> {
        match address {
            Address::DomainAddress(var_len, port) => {
                let host_str = String::from_utf8_lossy(&var_len.data);
                let addr_string = format!("{}:{}", host_str, port);

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
}

impl fmt::Debug for TunnelCommunity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelCommunity").finish_non_exhaustive()
    }
}
