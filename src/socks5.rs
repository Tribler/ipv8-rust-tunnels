use arc_swap::ArcSwap;
use rand::seq::SliceRandom;
use socks5_proto::{Address, UdpHeader};
use std::io::Cursor;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::{collections::HashMap, net::SocketAddr};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::payload;
use crate::routing::circuit::{Circuit, CircuitType};
use crate::socket::TunnelSettings;

#[derive(Debug, Clone)]
pub struct UDPAssociate {
    pub socket: Arc<UdpSocket>,
    pub handle: Arc<JoinHandle<()>>,
    pub default_remote: Option<SocketAddr>,
    pub hops: u8,
}

pub async fn handle_associate(
    associated_socket: Arc<UdpSocket>,
    tunnel_socket: Arc<UdpSocket>,
    circuits: Arc<Mutex<HashMap<u32, Circuit>>>,
    settings: Arc<ArcSwap<TunnelSettings>>,
    hops: u8,
) -> Result<(), String> {
    let mut connected = false;
    let mut buf = [0; 2048];
    let mut addr_to_cid: HashMap<Address, u32> = HashMap::new();

    info!(
        "Listening on UDP associate socket {} ({} hops)",
        associated_socket.local_addr().unwrap(),
        hops
    );

    loop {
        match associated_socket.recv_from(&mut buf).await {
            Ok((size, address)) => {
                if !connected {
                    if let Err(e) = associated_socket.connect(address).await {
                        return Err(format!("Error while calling socket.connect: {:?}", e));
                    };
                    connected = true;
                }

                let Some((target, cell, circuit_id)) = process_socks5_packet(
                    &associated_socket,
                    &circuits,
                    &settings,
                    &mut addr_to_cid,
                    &buf[..size],
                )
                .await
                else {
                    continue;
                };

                match tunnel_socket.send_to(&cell, target).await {
                    Ok(_) => debug!("Forwarded data from SOCKS5 to circuit {}", circuit_id),
                    Err(_) => error!("Could not tunnel cell for circuit {}", circuit_id),
                };
            }
            Err(e) => return Err(format!("Error while reading SOCK5 socket {:?}", e)),
        }
    }
}

async fn process_socks5_packet(
    associated_socket: &Arc<UdpSocket>,
    circuits: &Arc<Mutex<HashMap<u32, Circuit>>>,
    settings: &Arc<ArcSwap<TunnelSettings>>,
    addr_to_cid: &mut HashMap<Address, u32>,
    buf: &[u8],
) -> Option<(SocketAddr, Vec<u8>, u32)> {
    let header = match UdpHeader::read_from(&mut Cursor::new(buf)).await {
        Ok(header) => header,
        Err(_) => {
            error!("Failed to decode SOCKS5 header address");
            return None;
        }
    };

    let pkt = &buf[header.serialized_len()..].to_vec();
    let address = &header.address;
    let Some(circuit_id) = select_circuit(address, associated_socket, circuits, addr_to_cid) else {
        warn!("No circuits available, dropping packet");
        return None;
    };

    match circuits.lock().unwrap().get_mut(&circuit_id) {
        Some(circuit) => {
            if circuit.socket.is_none() {
                circuit.socket = Some(associated_socket.clone());
                info!("Associated socket for circuit {}", circuit_id);
            }

            let guard = settings.load();
            let max_relay_early = guard.max_relay_early;
            let prefix = &guard.prefix;
            let origin = Address::SocketAddress(SocketAddr::from((Ipv4Addr::from(0), 0)));
            let cell = payload::as_data_cell(prefix, circuit_id, &address, &origin, pkt);

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

fn select_circuit(
    address: &Address,
    socket: &Arc<UdpSocket>,
    circuits: &Arc<Mutex<HashMap<u32, Circuit>>>,
    addr_to_cid: &mut HashMap<Address, u32>,
) -> Option<u32> {
    // Deal with hidden services
    if let Address::SocketAddress(SocketAddr::V4(addr)) = address {
        if addr.port() == 1024 {
            let cid = payload::ip_to_circuit_id(addr.ip());
            if let Some(circuit) = circuits.lock().unwrap().get(&cid) {
                if (circuit.circuit_type == CircuitType::RPDownloader
                    || circuit.circuit_type == CircuitType::RPSeeder)
                    && (circuit.keys.len() == circuit.goal_hops as usize)
                {
                    return Some(cid);
                }
            }
        }
    }

    // Remove dead circuits from addr_to_cid
    if let Some(cid) = addr_to_cid.get(address) {
        if !circuits.lock().unwrap().contains_key(cid) {
            debug!("Not sending packet for {} over dead circuit {}, removing link", address, cid);
            addr_to_cid.remove(address);
        }
    }

    // Return the circuit_id that's assigned to this address, or return a random circuit_id (if available)
    match addr_to_cid.get(address) {
        Some(cid) => Some(*cid),
        None => {
            let options = get_options(&socket, &circuits);
            let Some(&cid) = options.choose(&mut rand::thread_rng()) else {
                return None;
            };
            addr_to_cid.insert(address.clone(), cid);
            Some(cid)
        }
    }
}

fn get_options(socket: &Arc<UdpSocket>, circuits: &Arc<Mutex<HashMap<u32, Circuit>>>) -> Vec<u32> {
    let guard = circuits.lock().unwrap();
    guard
        .values()
        .filter(|c| {
            c.data_ready() && (c.socket.is_none() || Arc::ptr_eq(c.socket.as_ref().unwrap(), &socket))
        })
        .map(|c| c.circuit_id)
        .collect()
}
