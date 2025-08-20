use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use tokio::net::UdpSocket;

use crate::{
    request_cache::RequestCache,
    routing::{circuit::Circuit, exit::ExitSocket, relay::RelayRoute},
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
}

impl RoutingTable {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            stats: Arc::new(Mutex::new(Stats::new())),
            circuits: Arc::new(Mutex::new(HashMap::new())),
            relays: Arc::new(Mutex::new(HashMap::new())),
            exits: Arc::new(Mutex::new(HashMap::new())),
            request_cache: RequestCache::new(),
        }
    }
}
