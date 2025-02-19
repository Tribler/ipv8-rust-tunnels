use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use arc_swap::ArcSwap;
use socks5_proto::Address;
use tokio::{net::UdpSocket, task::JoinHandle};

use crate::{
    crypto::{Direction, SessionKeys},
    payload,
    socket::TunnelSettings,
    stats::Stats,
    util,
};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum PeerFlag {
    Relay = 1,
    ExitBt = 2,
    ExitIpv8 = 4,
    SpeedTest = 8,
}

#[derive(Debug)]
pub struct ExitSocket {
    pub circuit_id: u32,
    pub peer: SocketAddr,
    pub keys: Vec<SessionKeys>,
    pub bytes_up: u32,
    pub bytes_down: u32,
    pub last_activity: u64,
    pub socket: Option<Arc<UdpSocket>>,
    pub handle: Option<JoinHandle<()>>,
}

impl ExitSocket {
    pub fn new(circuit_id: u32) -> Self {
        ExitSocket {
            circuit_id,
            peer: SocketAddr::from((Ipv4Addr::from(0), 0)),
            keys: Vec::new(),
            bytes_up: 0,
            bytes_down: 0,
            last_activity: 0,
            socket: None,
            handle: None,
        }
    }

    pub fn open_socket(&mut self, addr: SocketAddr) {
        self.socket = Some(match util::create_socket(addr) {
            Ok(socket) => {
                let addr = socket.local_addr().unwrap();
                info!("Exit {} listening on: {:?}", self.circuit_id, addr);
                socket
            }
            Err(e) => {
                error!("Error while opening exit socket {}: {}", self.circuit_id, e);
                return;
            }
        });
    }

    pub fn encrypt_outgoing_cell(&mut self, packet: Vec<u8>) -> Result<Vec<u8>, String> {
        let encrypted_cell = payload::encrypt_cell(&packet, Direction::Backward, &mut self.keys)?;
        Ok(encrypted_cell)
    }

    pub fn decrypt_incoming_cell(
        &mut self,
        packet: &[u8],
        max_relay_early: u8,
    ) -> Result<Vec<u8>, String> {
        let decrypted_cell = payload::decrypt_cell(packet, Direction::Forward, &self.keys)?;
        self.bytes_up += packet.len() as u32;
        self.last_activity = util::get_time();
        payload::check_cell_flags(&decrypted_cell, max_relay_early)?;
        Ok(decrypted_cell)
    }

    pub fn process_incoming_cell(
        &mut self,
        decrypted_cell: Vec<u8>,
    ) -> Result<(Address, Vec<u8>), String> {
        let tunnel_pkt = payload::unwrap_cell(&decrypted_cell);
        if tunnel_pkt.len() <= 36 {
            return Err("Got data packet of unexpected size".to_owned());
        }

        let (address, offset) = payload::decode_address(&tunnel_pkt, 27)?;
        let (_, offset) = payload::decode_address(&tunnel_pkt, offset)?;
        let exit_pkt = &tunnel_pkt[offset..];
        Ok((address, exit_pkt.to_vec()))
    }

    pub async fn listen_forever(
        tunnel_socket: Arc<UdpSocket>,
        stats: Arc<Mutex<Stats>>,
        exits: Arc<Mutex<HashMap<u32, ExitSocket>>>,
        circuit_id: u32,
        settings: Arc<ArcSwap<TunnelSettings>>,
    ) -> Result<(), String> {
        let socket = Self::get_socket(circuit_id, &exits)?;
        let mut buf = [0; 2048];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((size, mut socket_addr)) => {
                    // Convert mapped IPv4
                    if let IpAddr::V6(addr) = socket_addr.ip() {
                        if let Some(ipv4_addr) = addr.to_ipv4_mapped() {
                            socket_addr.set_ip(IpAddr::V4(ipv4_addr));
                        }
                    }

                    let guard = settings.load();
                    let prefix = &guard.prefix;
                    if let Err(e) = Self::check_if_allowed(&buf[..size], prefix, &guard.peer_flags) {
                        debug!("{}", e);
                        continue;
                    }

                    let (target, cell) = match exits.lock().unwrap().get_mut(&circuit_id) {
                        None => {
                            info!("Packet for unknown exit socket {}, stopping loop", circuit_id);
                            return Ok(());
                        }
                        Some(exit) => {
                            exit.bytes_down += size as u32;
                            let dest = Address::SocketAddress(SocketAddr::from((Ipv4Addr::from(0), 0)));
                            let origin = Address::SocketAddress(socket_addr);
                            let pkt = &buf[..size].to_vec();
                            let cell = payload::as_data_cell(prefix, circuit_id, &dest, &origin, pkt);

                            let Ok(encrypted_cell) =
                                payload::encrypt_cell(&cell, Direction::Backward, &mut exit.keys)
                            else {
                                error!("Error while encrypting cell for exit {}", circuit_id);
                                continue;
                            };

                            (exit.peer.clone(), encrypted_cell)
                        }
                    };
                    match tunnel_socket.send_to(&cell, target).await {
                        Ok(n) => {
                            stats.lock().unwrap().add_up(&cell, n);
                            debug!("Forwarded packet from {} to {}", socket_addr, circuit_id)
                        }
                        Err(_) => error!("Could not tunnel cell for exit {}", circuit_id),
                    };
                }
                Err(e) => {
                    return Err(format!("Error while reading exit socket: {:?}", e));
                }
            }
        }
    }

    pub fn get_socket(
        circuit_id: u32,
        exits: &Arc<Mutex<HashMap<u32, ExitSocket>>>,
    ) -> Result<Arc<UdpSocket>, String> {
        match exits.lock().unwrap().get(&circuit_id) {
            Some(exit) => {
                if exit.socket.is_none() {
                    return Err(format!("Could not find socket for exit {}", circuit_id));
                }
                Ok(exit.socket.clone().unwrap())
            }
            None => return Err(format!("Could not find exit {}", circuit_id)),
        }
    }

    pub fn check_if_allowed(
        packet: &[u8],
        prefix: &Vec<u8>,
        peer_flags: &HashSet<PeerFlag>,
    ) -> Result<(), String> {
        let is_bt = payload::could_be_bt(packet);
        let is_ipv8 = payload::could_be_ipv8(packet);

        if !(is_bt && peer_flags.contains(&PeerFlag::ExitBt))
            && !(is_ipv8 && peer_flags.contains(&PeerFlag::ExitIpv8))
            && !(is_ipv8 && prefix[..] == packet[..22])
        {
            return Err(format!(
                "Dropping data packets, refusing to be an exit node (BT={}, IPv8={}). Flags are {:?}",
                is_bt, is_ipv8, peer_flags
            ));
        }
        Ok(())
    }
}
