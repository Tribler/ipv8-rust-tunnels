use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use arc_swap::ArcSwap;
use pyo3::pyclass;
use tokio::net::UdpSocket;
use tokio::sync::{OnceCell, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::community::routing::{peer::PeerFlag, table::RoutingTable};
use crate::community::serialization::{could_be_bt, could_be_ipv8, Address, CellPayload};
use crate::crypto::cipher::{Direction, SessionKeys};
use crate::transport::stats::AtomicStat;
use crate::util;

#[derive(Debug)]
pub struct ExitSocket {
    pub circuit_id: u32,
    pub peer: SocketAddr,
    pub http_requests: Arc<Semaphore>,
    pub creation_time: u64,

    pub keys: ArcSwap<Vec<SessionKeys>>,
    pub socket: OnceCell<Arc<UdpSocket>>,
    pub token: CancellationToken,
    pub is_introduction: AtomicBool,
    pub is_rendezvous: AtomicBool,
    pub stats: AtomicStat,
}

impl ExitSocket {
    pub fn new(circuit_id: u32) -> Self {
        ExitSocket {
            circuit_id,
            peer: SocketAddr::from((Ipv4Addr::from(0), 0)),
            http_requests: Arc::new(Semaphore::new(5)),
            creation_time: util::get_time(),
            keys: ArcSwap::from_pointee(Vec::new()),
            socket: OnceCell::new(),
            token: CancellationToken::new(),
            is_introduction: AtomicBool::new(false),
            is_rendezvous: AtomicBool::new(false),
            stats: AtomicStat {
                num_up: std::sync::atomic::AtomicU64::new(0),
                num_down: std::sync::atomic::AtomicU64::new(0),
                bytes_up: std::sync::atomic::AtomicU64::new(0),
                bytes_down: std::sync::atomic::AtomicU64::new(0),
                last_received: std::sync::atomic::AtomicU64::new(util::get_time()),
            },
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.socket.initialized()
    }

    pub fn create_socket(&self, rt: RoutingTable, addr: SocketAddr) -> Option<&Arc<UdpSocket>> {
        match util::create_socket(addr) {
            Ok(socket) => {
                let local_addr = socket.local_addr().unwrap();
                info!("Exit {} listening on: {:?}", self.circuit_id, local_addr);

                match self.socket.set(socket.clone()) {
                    Ok(()) => {
                        let circuit_id = self.circuit_id;
                        let rt_clone = rt.clone();

                        rt_clone.task_manager.clone().spawn("exit_socket", async move {
                            if let Err(e) = ExitSocket::listen_forever(circuit_id, rt_clone).await {
                                error!("Error for exit {}: {}", circuit_id, e);
                            }
                        });

                        self.socket.get()
                    }
                    Err(_) => {
                        // Some other task set the socket before we did, so return that.
                        self.socket.get()
                    }
                }
            }
            Err(e) => {
                error!("Error while opening exit socket {}: {}", self.circuit_id, e);
                None
            }
        }
    }

    pub fn add_layer(&self, cell: &mut CellPayload) -> Result<(), String> {
        cell.encrypt(Direction::Backward, &self.keys.load())?;
        Ok(())
    }

    pub fn remove_layer(&self, cell: &mut CellPayload) -> Result<(), String> {
        cell.decrypt(Direction::Forward, &self.keys.load())?;
        Ok(())
    }

    pub fn process(&self, cell: &mut CellPayload, is_inbound: bool) -> Result<Option<SocketAddr>, String> {
        if is_inbound {
            cell.check(1, self.is_enabled())?;
            self.stats.add_up(cell.len());
            Ok(None)
        } else {
            self.stats.add_down(cell.len(), util::get_time());
            Ok(Some(self.peer))
        }
    }

    pub async fn listen_forever(circuit_id: u32, rt: RoutingTable) -> Result<(), String> {
        let socket = Self::get_socket(rt.clone(), circuit_id)?;

        let exit_guard = rt.exits.load();
        let Some(exit) = exit_guard.get(&circuit_id) else {
            return Err(format!("Could not find exit {}", circuit_id));
        };

        let token = exit.token.clone();

        token
            .run_until_cancelled(async move {
                loop {
                    let mut buf = vec![0u8; 2048];

                    match socket.recv_from(&mut buf).await {
                        Ok((0, _)) => continue,
                        Ok((size, socket_addr)) => {
                            buf.truncate(size);
                            Self::on_packet(circuit_id, rt.clone(), socket_addr, buf).await;
                        }
                        Err(e) => {
                            error!("Error while reading exit socket {}: {:?}", circuit_id, e);
                            break;
                        }
                    }
                }
            })
            .await;
        debug!("Exit socket loop {} terminated cleanly.", circuit_id);
        Ok(())
    }

    async fn on_packet(circuit_id: u32, rt: RoutingTable, mut socket_addr: SocketAddr, packet: Vec<u8>) {
        // Convert mapped IPv4
        if let IpAddr::V6(addr) = socket_addr.ip() {
            if let Some(ipv4_addr) = addr.to_ipv4_mapped() {
                socket_addr.set_ip(IpAddr::V4(ipv4_addr));
            }
        }

        let guard = rt.settings.load();
        let prefix = &guard.prefix;
        if let Err(e) = Self::check_if_allowed(&packet, prefix, &guard.peer_flags) {
            debug!("{}", e);
            return;
        }

        let (target, buffer) = match rt.exits.load().get(&circuit_id) {
            None => {
                info!("Packet for unknown exit socket {}, dropping packet", circuit_id);
                return;
            }
            Some(exit) => {
                let dest = Address::V4(SocketAddrV4::new(Ipv4Addr::from(0), 0));
                let origin = match socket_addr {
                    SocketAddr::V4(addr) => Address::V4(addr),
                    SocketAddr::V6(addr) => Address::V6(addr),
                };

                let mut buffer = match rt.outbound_pool.pull().await {
                    Ok(b) => b,
                    Err(e) => {
                        error!("Exit worker failed to acquire pool buffer: {}", e);
                        return;
                    }
                };
                let raw_buf = buffer.inner.as_mut().unwrap();

                let mut cell = match CellPayload::from_data(circuit_id, &dest, &origin, &packet, raw_buf) {
                    Ok(c) => c,
                    Err(e) => {
                        error!("Error creating data cell for exit {circuit_id}: {e}");
                        return;
                    }
                };

                if let Err(error) = exit.add_layer(&mut cell) {
                    error!("Error encrypting cell for exit {circuit_id}: {error}");
                    return;
                }

                exit.stats.add_down(packet.len(), util::get_time());

                (exit.peer.clone(), buffer)
            }
        };

        match rt.send_packet(target, buffer).await {
            Ok(_) => {
                debug!("Forwarded packet from {} to {}", socket_addr, circuit_id)
            }
            Err(_) => error!("Could not tunnel cell for exit {}", circuit_id),
        };
    }

    pub fn get_socket(rt: RoutingTable, circuit_id: u32) -> Result<Arc<UdpSocket>, String> {
        match rt.exits.load().get(&circuit_id) {
            Some(exit) => {
                if let Some(socket_arc) = exit.socket.get().as_ref() {
                    Ok(Arc::clone(socket_arc))
                } else {
                    Err(format!("Could not find socket for exit {}", circuit_id))
                }
            }
            None => return Err(format!("Could not find exit {}", circuit_id)),
        }
    }

    pub fn check_if_allowed(
        packet: &[u8],
        prefix: &Vec<u8>,
        peer_flags: &HashSet<PeerFlag>,
    ) -> Result<(), String> {
        let is_bt = could_be_bt(packet);
        let is_ipv8 = could_be_ipv8(packet);

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

impl Drop for ExitSocket {
    fn drop(&mut self) {
        debug!("Stopping exit {} socket and thread", self.circuit_id);
        self.token.cancel();
        self.socket.take();
    }
}

#[pyclass(get_all)]
#[derive(Clone)]
pub struct PyExitStats {
    pub circuit_id: u32,
    pub enabled: bool,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub creation_time: u64,
    pub is_introduction: bool,
    pub is_rendezvous: bool,
}
