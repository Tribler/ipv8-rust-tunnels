use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use arc_swap::ArcSwap;
use tokio::net::UdpSocket;

use crate::util::Result;
use crate::{
    packet::wrap_cell,
    request_cache::RequestCache,
    routing::{circuit::Circuit, exit::ExitSocket, relay::RelayRoute},
    socket::TunnelSettings,
    stats::Stats,
};

#[derive(Debug, Clone)]
pub struct RoutingTable {
    pub socket: Arc<UdpSocket>,
    pub stats: Arc<Mutex<Stats>>,
    pub circuits: Arc<Mutex<HashMap<u32, Circuit>>>,
    pub relays: Arc<Mutex<HashMap<u32, RelayRoute>>>,
    pub exits: Arc<Mutex<HashMap<u32, ExitSocket>>>,
    pub request_cache: RequestCache,
    pub settings: Arc<ArcSwap<TunnelSettings>>,
}

impl RoutingTable {
    pub fn new(socket: Arc<UdpSocket>, settings: Arc<ArcSwap<TunnelSettings>>) -> Self {
        Self {
            socket,
            stats: Arc::new(Mutex::new(Stats::new())),
            circuits: Arc::new(Mutex::new(HashMap::new())),
            relays: Arc::new(Mutex::new(HashMap::new())),
            exits: Arc::new(Mutex::new(HashMap::new())),
            request_cache: RequestCache::new(),
            settings,
        }
    }

    pub async fn send_cell(
        &self,
        circuit_id: u32,
        payload: &impl deku::DekuContainerWrite,
    ) -> Result<usize> {
        let payload_data = payload.to_bytes().unwrap();
        let cell = wrap_cell(&payload_data);
        let (encrypted_cell, target) = match self.circuits.lock().unwrap().get_mut(&circuit_id) {
            Some(circuit) => (
                circuit.encrypt_outgoing_cell(cell, self.settings.load().max_relay_early)?,
                circuit.peer.clone(),
            ),
            None => match self.exits.lock().unwrap().get_mut(&circuit_id) {
                Some(exit) => (exit.encrypt_outgoing_cell(cell)?, exit.peer.clone()),
                None => return Err(format!("unknown circuit {}", circuit_id)),
            },
        };

        match self.socket.send_to(&encrypted_cell, target).await {
            Ok(bytes) => {
                self.stats
                    .lock()
                    .unwrap()
                    .add_up(&encrypted_cell, encrypted_cell.len());
                Ok(bytes)
            }
            Err(e) => Err(format!("{}", e)),
        }
    }
}
