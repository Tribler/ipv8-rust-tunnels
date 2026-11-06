use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::{ArcSwap, ArcSwapOption};
use bencode::{Bencode, FromBencode, ToBencode};
use dashmap::DashMap;
use deku::{DekuContainerRead, DekuContainerWrite};
use pyo3::{pyclass, Py, PyAny};
use rand::seq::IndexedRandom;
use tokio::sync::oneshot;

use crate::community::routing::circuit::CircuitType::{self};
use crate::community::routing::circuit::{Circuit, CircuitState, Hop};
use crate::community::routing::exit::ExitSocket;
use crate::community::routing::peer::PeerFlag;
use crate::community::routing::rendezvous::Rendezvous;
use crate::community::serialization::{
    circuit_id_to_ip, ip_to_circuit_id, unpack_cell_payload, Address, CellId, CreateE2EPayload,
    CreatedE2EPayload, DataPayload, EstablishIntroPayload, EstablishRendezvousPayload,
    IntroEstablishedPayload, LinkE2EPayload, LinkedE2EPayload, MessageId, Raw, RendezvousEstablishedPayload,
    RendezvousInfo, VarLenH,
};
use crate::community::tunnels::TunnelCommunity;
use crate::crypto::cipher::{Direction, SessionKeys};
use crate::crypto::keys::{PrivateKey, PublicKey};
use crate::dht::engine::DHTWrapper;
use crate::dht::serialization::{
    serialize_address_compact, unserialize_address_compact, unwrap_dict, BencodeMapExt, DhtMessage,
};
use crate::peer::Peer;
use crate::request_cache::CacheResult;
use crate::util::{to_hex, Future, Result};

impl DhtMessage for IPRequest {
    type Response = IPResponse;
    const METHOD: &'static [u8] = b"get_ips";
}

#[derive(Debug, Clone)]
pub struct IPRequest {
    pub id: [u8; 20],
    pub info_hash: [u8; 20],
}
impl ToBencode for IPRequest {
    fn to_bencode(&self) -> Bencode {
        let mut m = BTreeMap::new();
        m.set_bytes("id", self.id.to_vec());
        m.set_bytes("info_hash", self.info_hash.to_vec());
        Bencode::Dict(m)
    }
}
impl FromBencode for IPRequest {
    type Err = String;
    fn from_bencode(b: &Bencode) -> Result<Self> {
        let m = unwrap_dict(b)?;
        Ok(IPRequest { id: m.get_array("id")?, info_hash: m.get_array("info_hash")? })
    }
}

#[derive(Debug, Clone)]
pub struct IPResponse {
    pub id: [u8; 20],
    pub info_hash: [u8; 20],
    pub peers: Option<Vec<IntroductionPoint>>,
}

impl ToBencode for IPResponse {
    fn to_bencode(&self) -> Bencode {
        let mut m = BTreeMap::new();
        m.set_bytes("id", self.id.to_vec());
        m.set_bytes("info_hash", self.info_hash.to_vec());
        m.set_list("peers", &self.peers, |p| p.to_bencode());
        Bencode::Dict(m)
    }
}
impl FromBencode for IPResponse {
    type Err = String;
    fn from_bencode(b: &Bencode) -> Result<Self> {
        let m = unwrap_dict(b)?;
        let id = m.get_array("id")?;
        let info_hash = m.get_array("info_hash")?;
        let peers = m.get_list("peers", true, |item| IntroductionPoint::from_bencode(&item))?;
        Ok(IPResponse { id, info_hash, peers })
    }
}

#[derive(Debug, Clone, Eq)]
pub struct IntroductionPoint {
    pub address: SocketAddr,
    pub key: Vec<u8>,
    pub seeder_pk: Vec<u8>,
    pub source: u8,
    pub last_seen: u64,
}

impl IntroductionPoint {
    pub fn new(
        address: SocketAddr,
        key: Vec<u8>,
        seeder_pk: Vec<u8>,
        source: u8,
        last_seen: Option<u64>,
    ) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        Self { address, key, seeder_pk, source, last_seen: last_seen.unwrap_or(now) }
    }

    pub fn peer(&self) -> Result<Peer> {
        Ok(Peer {
            address: self.address,
            public_key: PublicKey::from_bytes(&self.key)
                .map_err(|e| format!("Invalid key for introduction point: {e}"))?,
            private_key: None,
        })
    }
}

impl PartialEq for IntroductionPoint {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address && self.seeder_pk == other.seeder_pk
    }
}

impl std::hash::Hash for IntroductionPoint {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.address.hash(state);
        self.seeder_pk.hash(state);
    }
}

impl ToBencode for IntroductionPoint {
    fn to_bencode(&self) -> Bencode {
        let mut m = std::collections::BTreeMap::new();
        m.set_bytes("address", serialize_address_compact(&self.address).to_vec());
        m.set_bytes("key", self.key.clone());
        m.set_bytes("seeder_pk", self.seeder_pk.clone());
        m.set_num("source", self.source as i64);
        Bencode::Dict(m)
    }
}

impl FromBencode for IntroductionPoint {
    type Err = String;
    fn from_bencode(b: &Bencode) -> Result<Self> {
        let m = unwrap_dict(b)?;
        let raw_addr = m.get_bytes("address")?;
        let address = unserialize_address_compact(&raw_addr)?;
        let key = m.get_bytes("key")?;
        let seeder_pk = m.get_bytes("seeder_pk")?;
        let source = m.get_num("source")? as u8;
        Ok(Self::new(address, key, seeder_pk, source, None))
    }
}

pub enum E2ECallback {
    // E2ECallback can be Rust or Python
    Rust(Arc<dyn Fn([u8; 20], std::net::IpAddr, u16) -> std::result::Result<(), String> + Send + Sync>),
    Python(Py<PyAny>),
}

impl Clone for E2ECallback {
    fn clone(&self) -> Self {
        match self {
            E2ECallback::Rust(f) => E2ECallback::Rust(Arc::clone(f)),
            E2ECallback::Python(p) => pyo3::Python::attach(|py| E2ECallback::Python(p.clone_ref(py))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct E2ERequestCache {
    pub info_hash: [u8; 20],
    pub hop: Hop,
    pub intro_point: IntroductionPoint,
}

#[derive(Debug, Clone)]
pub struct LinkRequestCache {
    pub circuit: Arc<Circuit>,
    pub info_hash: [u8; 20],
    pub session_keys: Arc<SessionKeys>,
}

#[derive(Debug, Clone)]
pub struct PeersRequestCache {
    pub info_hash: [u8; 20],
    pub identifier: u16,
    pub future_tx: Arc<Mutex<Option<oneshot::Sender<Vec<IntroductionPoint>>>>>,
}

pub struct HiddenServiceState {
    pub swarms: ArcSwap<HashMap<[u8; 20], Arc<Swarm>>>,
    pub intro_point_for: DashMap<Vec<u8>, (Arc<ExitSocket>, [u8; 20])>,
    pub rendezvous_point_for: DashMap<[u8; 20], Arc<ExitSocket>>,
    /// Track create-e2e payload, so we know what to do with the created-e2e response.
    pub introduction_bridges: DashMap<(u32, u16), u32>,
    pub e2e_callback: ArcSwapOption<E2ECallback>,
    pub dht: ArcSwapOption<DHTWrapper>,
}

impl HiddenServiceState {
    pub fn new(e2e_callback: Option<Py<PyAny>>) -> Self {
        let cb = e2e_callback.map(|obj| Arc::new(E2ECallback::Python(obj)));
        Self {
            swarms: ArcSwap::new(Arc::new(HashMap::new())),
            intro_point_for: DashMap::new(),
            rendezvous_point_for: DashMap::new(),
            introduction_bridges: DashMap::new(),
            e2e_callback: ArcSwapOption::new(cb),
            dht: ArcSwapOption::empty(),
        }
    }

    pub fn set_swarm(&self, info_hash: [u8; 20], swarm: Swarm) {
        let swarm_arc = Arc::new(swarm);
        self.swarms.rcu(|current| {
            let mut next = current.as_ref().clone();
            next.insert(info_hash, Arc::clone(&swarm_arc));
            next
        });
    }

    pub fn remove_broken_ips(&self, target_circuit_id: u32) {
        let dht_guard = self.dht.load();
        self.intro_point_for.retain(|_public_key, (exit, info_hash)| {
            if exit.circuit_id == target_circuit_id {
                if let Some(dht_handle) = dht_guard.as_ref() {
                    info!("Stop DHT announce for infohash {}", to_hex(&*info_hash));
                    dht_handle.stop_announce(&*info_hash);
                }
                false
            } else {
                true
            }
        });
        self.rendezvous_point_for.retain(|_, exit| exit.circuit_id != target_circuit_id);
        self.introduction_bridges.retain(|_, client_cid| *client_cid != target_circuit_id);
    }

    pub fn call_e2e_callback(
        &self,
        infohash: &[u8; 20],
        virtual_ip: std::net::IpAddr,
        port: u16,
    ) -> Result<()> {
        let callback_guard = self.e2e_callback.load();
        let Some(callback) = callback_guard.as_ref() else {
            warn!("No e2e_callback set!");
            return Ok(());
        };

        match callback.as_ref() {
            E2ECallback::Rust(rust_fn) => rust_fn(*infohash, virtual_ip, port),
            E2ECallback::Python(py_fn) => pyo3::Python::attach(|py| {
                let py_infohash = pyo3::types::PyBytes::new(py, infohash);
                let py_addr = (virtual_ip.to_string(), port);

                py_fn
                    .call1(py, (py_infohash, py_addr))
                    .map(|_| ())
                    .map_err(|e| format!("Exception in Python e2e_callback(): {e}"))
            }),
        }
    }
}

pub struct RendezvousPoint {
    pub circuit: Arc<Circuit>,
    pub cookie: [u8; 20],
    pub address: Future<Address>,
}

impl RendezvousPoint {
    pub fn new(circuit: Arc<Circuit>, cookie: [u8; 20]) -> Self {
        Self { circuit, cookie, address: Future::new() }
    }
}

pub struct Swarm {
    pub info_hash: [u8; 20],
    pub hops: u8,
    pub seeder_sk: Option<PrivateKey>,
    pub max_ip_age: u64,
    pub seeding: AtomicBool,

    pub intro_points: Mutex<Vec<IntroductionPoint>>,
    pub connections: Mutex<HashMap<u32, (Arc<Circuit>, IntroductionPoint)>>,
    pub last_lookup: AtomicU64,
    pub transfer_history_up: AtomicU64,
    pub transfer_history_down: AtomicU64,
}

impl Swarm {
    pub fn new(info_hash: [u8; 20], hops: u8, seeder_sk: Option<PrivateKey>, max_ip_age: u64) -> Self {
        Self {
            info_hash,
            hops,
            seeder_sk,
            max_ip_age,
            seeding: AtomicBool::new(false),
            intro_points: Mutex::new(Vec::new()),
            connections: Mutex::new(HashMap::new()),
            last_lookup: AtomicU64::new(0),
            transfer_history_up: AtomicU64::new(0),
            transfer_history_down: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn is_seeding(&self) -> bool {
        self.seeder_sk.is_some()
    }

    pub fn add_connection(&self, rp_circuit: Arc<Circuit>, intro_point_used: IntroductionPoint) {
        self.connections
            .lock()
            .unwrap()
            .entry(rp_circuit.circuit_id)
            .or_insert((rp_circuit, intro_point_used));
    }

    pub fn remove_connection(&mut self, circuit_id: u32) -> bool {
        if let Some((circuit, _)) = self.connections.lock().unwrap().remove(&circuit_id) {
            self.transfer_history_up
                .fetch_add(circuit.stats.bytes_up.load(Ordering::Relaxed), Ordering::Relaxed);

            self.transfer_history_down
                .fetch_add(circuit.stats.bytes_down.load(Ordering::Relaxed), Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    pub fn has_connection(&self, seeder_pk: &[u8]) -> bool {
        let lock = self.connections.lock().unwrap();
        lock.values().any(|(_, ip)| ip.seeder_pk == seeder_pk)
    }

    pub fn add_intro_point(&self, ip: IntroductionPoint) -> IntroductionPoint {
        let position = self.intro_points.lock().unwrap().iter().position(|i| i.seeder_pk == ip.seeder_pk);

        let mut guard = self.intro_points.lock().unwrap();
        if let Some(idx) = position {
            guard[idx].last_seen = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            guard[idx].clone()
        } else {
            guard.push(ip.clone());
            ip
        }
    }

    pub fn remove_intro_point(&mut self, ip: &IntroductionPoint) {
        if let Some(pos) = self.intro_points.lock().unwrap().iter().position(|i| i == ip) {
            self.intro_points.lock().unwrap().remove(pos);
        }
    }

    pub fn remove_old_intro_points(&self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let used_intro_points: HashSet<IntroductionPoint> = self
            .connections
            .lock()
            .unwrap()
            .values()
            .filter(|(c, _)| c.state() == CircuitState::Ready && c.is_e2e())
            .map(|(_, ip)| ip.clone())
            .collect();

        let max_age = self.max_ip_age;
        self.intro_points
            .lock()
            .unwrap()
            .retain(|i| (i.last_seen + max_age >= now) || used_intro_points.contains(i));
    }

    pub fn get_intro_points(&self) -> Vec<IntroductionPoint> {
        self.remove_old_intro_points();
        self.intro_points.lock().unwrap().clone()
    }

    pub fn get_random_intro_point(&self) -> Option<IntroductionPoint> {
        let lock = self.intro_points.lock().unwrap();
        if lock.is_empty() {
            return None;
        }
        lock.choose(&mut rand::rng()).cloned()
    }

    pub fn get_num_seeders(&self) -> usize {
        let mut seeder_pks: HashSet<Vec<u8>> =
            self.intro_points.lock().unwrap().iter().map(|ip| ip.seeder_pk.clone()).collect();

        for (_, ip) in self.connections.lock().unwrap().values() {
            seeder_pks.insert(ip.seeder_pk.clone());
        }
        seeder_pks.len()
    }

    pub fn get_num_connections(&self) -> usize {
        self.connections.lock().unwrap().len()
    }

    pub fn get_num_connections_complete(&self) -> usize {
        self.connections
            .lock()
            .unwrap()
            .values()
            .filter(|(c, _)| c.state() == CircuitState::Ready && c.is_e2e())
            .count()
    }

    pub fn get_num_connections_incomplete(&self) -> usize {
        self.get_num_connections() - self.get_num_connections_complete()
    }

    pub fn get_total_up(&self) -> u64 {
        let active_sum: u64 = self
            .connections
            .lock()
            .unwrap()
            .values()
            .map(|(c, _)| c.stats.bytes_up.load(Ordering::Relaxed))
            .sum();
        self.transfer_history_up.load(Ordering::Relaxed) + active_sum
    }

    pub fn get_total_down(&self) -> u64 {
        let active_sum: u64 = self
            .connections
            .lock()
            .unwrap()
            .values()
            .map(|(c, _)| c.stats.bytes_down.load(Ordering::Relaxed))
            .sum();
        self.transfer_history_down.load(Ordering::Relaxed) + active_sum
    }
}

impl TunnelCommunity {
    pub async fn on_message_hs(
        &self,
        _address: SocketAddr,
        _msg_id: MessageId,
        _buffer: &mut Vec<u8>,
    ) -> Result<()> {
        Ok(())
    }

    pub async fn on_cell_hs(
        &self,
        address: SocketAddr,
        circuit_id: u32,
        cell_id: CellId,
        buffer: &mut Vec<u8>,
    ) -> crate::util::Result<()> {
        match cell_id {
            CellId::EstablishIntro => Self::on_establish_intro(self, address, circuit_id, buffer).await,
            CellId::IntroEstablished => Self::on_intro_established(self, address, circuit_id, buffer).await,
            CellId::EstablishRendezvous => {
                Self::on_establish_rendezvous(self, address, circuit_id, buffer).await
            }
            CellId::RendezvousEstablished => {
                Self::on_rendezvous_established(self, address, circuit_id, buffer).await
            }
            CellId::CreatedE2E => Self::on_created_e2e(self, address, circuit_id, buffer).await,
            CellId::LinkE2E => Self::on_link_e2e(self, address, circuit_id, buffer).await,
            CellId::LinkedE2E => Self::on_linked_e2e(self, address, circuit_id, buffer).await,
            CellId::CreateE2E => Self::on_create_e2e(self, address, circuit_id, buffer).await,
            _ => Ok(()),
        }
    }

    pub fn start_peer_discovery(&self) {
        let tunnels = self.self_handle.get().expect("Self handle uninitialized").clone();

        self.rt.task_manager.spawn_interval("do_peer_discovery", Duration::from_secs(30), true, move || {
            let tunnels_clone = tunnels.clone();

            async move {
                let settings = tunnels_clone.rt.settings.load();
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

                let swarms_guard = tunnels_clone.hs_state.swarms.load();
                for (&info_hash, swarm) in swarms_guard.iter() {
                    if swarm.seeding.load(Ordering::Relaxed) {
                        continue;
                    }

                    let last_lookup = swarm.last_lookup.load(Ordering::Relaxed);
                    if last_lookup + settings.swarm_lookup_interval > now {
                        continue;
                    }

                    if swarm.get_num_connections() >= settings.swarm_connection_limit {
                        continue;
                    }

                    // Move timestamp first to avoid race conditions.
                    swarm.last_lookup.store(now, Ordering::Relaxed);
                    let _ = tunnels_clone.request_ip_lookup(&info_hash).await;
                }
            }
        });
    }

    pub fn join_swarm(&self, info_hash: [u8; 20], hops: u8, seeding: bool) -> Result<()> {
        let swarms_guard = self.hs_state.swarms.load();

        if swarms_guard.contains_key(&info_hash) {
            warn!(
                "Already part of hidden swarm {}, purging pre-existing connection trees.",
                to_hex(&info_hash)
            );
            self.leave_swarm(&info_hash);
        }

        let seeder_sk = if seeding {
            let sk = PrivateKey::generate("curve25519")
                .map_err(|e| format!("Crypto failure generating ephemeral seeder key: {e}"))?;
            Some(sk)
        } else {
            None
        };

        let new_swarm = Arc::new(Swarm {
            info_hash,
            hops,
            seeder_sk,
            max_ip_age: 3600,
            seeding: std::sync::atomic::AtomicBool::new(seeding),
            intro_points: std::sync::Mutex::new(Vec::new()),
            connections: std::sync::Mutex::new(HashMap::new()),
            last_lookup: std::sync::atomic::AtomicU64::new(0),
            transfer_history_up: std::sync::atomic::AtomicU64::new(0),
            transfer_history_down: std::sync::atomic::AtomicU64::new(0),
        });

        self.hs_state.swarms.rcu(|current_map| {
            let mut next_map = (**current_map).clone();
            next_map.insert(info_hash, Arc::clone(&new_swarm));
            next_map
        });

        info!("Successfully joined hidden swarm hash: {}", to_hex(&info_hash));
        Ok(())
    }

    pub fn leave_swarm(&self, info_hash: &[u8]) {
        self.hs_state.swarms.rcu(|current_map| {
            let mut next_map = (**current_map).clone();
            next_map.remove(info_hash);
            next_map
        });

        self.hs_state.intro_point_for.retain(|k, _| k != info_hash);
        self.hs_state.rendezvous_point_for.retain(|k, _| k != info_hash);
    }

    pub async fn create_introduction_point(
        &self,
        info_hash: &[u8; 20],
        required_ip: Option<Peer>,
    ) -> Result<()> {
        info!("Creating introduction point for swarm {}", to_hex(&info_hash));

        let seed_pk = {
            let swarms_guard = self.hs_state.swarms.load();
            let swarm = match swarms_guard.get(&info_hash[..]) {
                Some(s) => s,
                None => {
                    warn!("Cannot create introduction point for unknown swarm");
                    return Ok(());
                }
            };

            match &swarm.seeder_sk {
                Some(private_key) => private_key.public_key()?.key_to_bin()?,
                None => {
                    warn!("Cannot create introduction point for swarm that is not seeding");
                    return Ok(());
                }
            }
        };

        let circuit = self
            .create_circuit_with_retry(1, CircuitType::IPSeeder, None, required_ip, Some(info_hash.to_vec()))
            .await?;

        let identifier = self.request_cache.generate_identifier() as u16;
        self.request_cache.add_identifier("IntroRequestCache".to_owned(), identifier, Some(10), None);

        let payload = EstablishIntroPayload {
            circuit_id: circuit.circuit_id,
            identifier,
            info_hash: *info_hash,
            public_key: VarLenH { data_len: seed_pk.len() as u16, data: seed_pk },
        };

        self.rt.send_cell(&payload, None).await?;
        info!("Establishing introduction point using {}", circuit.circuit_id);

        Ok(())
    }

    pub async fn create_circuit_for_infohash(
        &self,
        info_hash: &[u8],
        ctype: CircuitType,
        exit_flags: Option<HashSet<PeerFlag>>,
        required_exit: Option<Peer>,
    ) -> Result<Arc<Circuit>> {
        let swarm_hops = {
            let swarms_guard = self.hs_state.swarms.load();
            let swarm = swarms_guard
                .get(info_hash)
                .ok_or_else(|| format!("infohash {} is not part of any joined swarm", to_hex(info_hash)))?;
            swarm.hops
        };

        // Introduction point circuits need an additional hop, or we will talk directly to the introduction point.
        // Also, rendezvous circuits need an additional hop, since the seeder chooses the rendezvous_point.
        let mut target_hops = swarm_hops;
        if ctype == CircuitType::IPSeeder
            || ctype == CircuitType::IPDownloader
            || ctype == CircuitType::RPDownloader
        {
            target_hops += 1;
        }

        self.create_circuit_with_retry(
            target_hops,
            ctype,
            exit_flags,
            required_exit,
            Some(info_hash.to_vec()),
        )
        .await
    }

    pub async fn on_establish_intro(
        &self,
        _source_address: SocketAddr,
        circuit_id: u32,
        cell: &mut Vec<u8>,
    ) -> Result<()> {
        let payload: EstablishIntroPayload = unpack_cell_payload(cell)?;
        let public_key = payload.public_key.data.clone();
        let infohash = payload.info_hash.clone();

        if self.hs_state.intro_point_for.contains_key(&public_key) {
            warn!("Already have an introduction point registered for: {}", to_hex(&public_key));
            return Ok(());
        }

        info!("Established introduction point for: {}", to_hex(&public_key));

        let exits = self.rt.exits.load();
        let Some(exit_socket) = exits.get(&circuit_id) else {
            warn!("Failed to establish introduction point for unknown circuit ID: {circuit_id}");
            return Ok(());
        };

        if exit_socket.is_enabled() {
            return Err("Circuit is already exiting data".to_owned());
        }
        exit_socket.is_introduction.store(true, Ordering::Relaxed);

        self.hs_state.intro_point_for.insert(public_key.clone(), (Arc::clone(exit_socket), infohash.clone()));

        self.start_ip_announce(payload.info_hash).await.expect("Failed to announce introduction point");

        let response_payload =
            IntroEstablishedPayload { circuit_id: exit_socket.circuit_id, identifier: payload.identifier };

        self.rt.send_cell(&response_payload, None).await?;
        Ok(())
    }

    pub async fn on_intro_established(
        &self,
        address: SocketAddr,
        _circuit_id: u32,
        cell: &mut Vec<u8>,
    ) -> Result<()> {
        let payload: IntroEstablishedPayload = unpack_cell_payload(cell)?;
        match self.request_cache.pop("IntroRequestCache", payload.identifier) {
            CacheResult::Identifier(_) => info!("Got intro-established from {:?}", address),
            _ => warn!("Invalid intro-established request identifier: {}", payload.identifier),
        }
        Ok(())
    }

    pub async fn create_rendezvous_point(&self, infohash: &[u8]) -> Result<Arc<RendezvousPoint>> {
        let circuit = self.create_circuit_for_infohash(infohash, CircuitType::RPSeeder, None, None).await?;

        if circuit.state() != CircuitState::Ready {
            return Err(format!("Aborting rendezvous setup: circuit {} not ready", circuit.circuit_id));
        }

        let circuit_id = circuit.circuit_id;
        let cookie = rand::random::<[u8; 20]>();
        let rp = Arc::new(RendezvousPoint::new(Arc::clone(&circuit), cookie.clone()));

        let identifier = self.request_cache.generate_identifier() as u16;
        self.request_cache.add_identifier(
            "RPRequestCache".to_owned(),
            identifier,
            Some(10),
            Some(rp.clone()),
        );

        let payload = EstablishRendezvousPayload { circuit_id, identifier, cookie };

        self.rt.send_cell(&payload, None).await.map_err(|e| {
            format!("Failed to send established-rendezvous for circuit {}: {}", circuit_id, e)
        })?;

        info!("Successfully sent established-rendezvous for circuit: {}", circuit_id);
        Ok(rp)
    }

    pub async fn on_establish_rendezvous(
        &self,
        _source_address: SocketAddr,
        circuit_id: u32,
        cell: &mut Vec<u8>,
    ) -> Result<()> {
        let payload: EstablishRendezvousPayload = unpack_cell_payload(cell)?;

        let exits = self.rt.exits.load();
        let Some(exit_socket) = exits.get(&circuit_id) else {
            warn!("Failed to establish rendezvous point for unknown circuit ID: {circuit_id}");
            return Ok(());
        };

        if exit_socket.is_enabled() {
            return Err("Circuit is already exiting data".to_owned());
        }
        exit_socket.is_rendezvous.store(true, Ordering::Relaxed);

        let cookie = payload.cookie.clone();
        info!("Establishing rendezvous point for: {}", to_hex(&cookie));

        self.hs_state.rendezvous_point_for.insert(cookie, Arc::clone(exit_socket));
        let my_wan = match self.rt.runtime.my_estimated_wan.load().clone() {
            Some(addr) => *addr,
            None => return Err("RuntimeContext my_estimated_wan not set".to_owned()),
        };

        let response_payload = RendezvousEstablishedPayload {
            circuit_id: exit_socket.circuit_id,
            identifier: payload.identifier,
            rendezvous_point_addr: my_wan.into(),
        };

        self.rt.send_cell(&response_payload, None).await?;
        Ok(())
    }

    pub async fn on_rendezvous_established(
        &self,
        source_address: SocketAddr,
        _circuit_id: u32,
        cell: &mut Vec<u8>,
    ) -> Result<()> {
        let payload: RendezvousEstablishedPayload = unpack_cell_payload(cell)?;

        let CacheResult::Identifier(Some(raw_data)) =
            self.request_cache.pop("RPRequestCache", payload.identifier)
        else {
            warn!("Invalid rendezvous-established request: {}", payload.identifier);
            return Ok(());
        };

        let Ok(rp) = raw_data.downcast::<RendezvousPoint>() else {
            warn!("Failed to downcast RPRequestCache data");
            return Ok(());
        };

        info!("Got rendezvous-established from {:?}", source_address);
        let addr: Address = payload.rendezvous_point_addr.into();
        let _ = rp.address.set(addr);
        Ok(())
    }

    pub fn select_circuit_for_infohash(&self, info_hash: &[u8]) -> Option<Arc<Circuit>> {
        let swarms = self.hs_state.swarms.load();
        let swarm = swarms.get(info_hash)?;
        if swarm.hops == 0 {
            info!("Can't get hop count for infohash swarm, download cancelled?");
            return None;
        }
        self.select_circuit(None, swarm.hops as u8)
    }

    pub fn select_circuit(&self, destination: Option<SocketAddr>, hops: u8) -> Option<Arc<Circuit>> {
        if let Some(SocketAddr::V4(dest_v4)) = destination {
            if dest_v4.port() == 1024 {
                let circuit_id = ip_to_circuit_id(dest_v4.ip());
                if let Some(circuit) = self.rt.circuits.load().get(&circuit_id) {
                    if circuit.state() == CircuitState::Ready
                        && circuit.circuit_type == CircuitType::RPDownloader
                    {
                        return Some(Arc::clone(circuit));
                    }
                }
            }
        }

        let circuits = self.rt.circuits.load();
        let candidates: Vec<Arc<Circuit>> = circuits
            .values()
            .filter(|c| c.goal_hops == hops && c.state() == CircuitState::Ready)
            .cloned()
            .collect();

        candidates.choose(&mut rand::rng()).cloned()
    }

    pub async fn create_e2e(&self, info_hash: &[u8; 20], intro_point: IntroductionPoint) -> Result<()> {
        let intro_peer = intro_point.peer()?;
        let circuit = self
            .create_circuit_for_infohash(info_hash, CircuitType::IPDownloader, None, Some(intro_peer.clone()))
            .await?;

        let dh_secret = PrivateKey::generate("curve25519")?;
        let dh_first_part = dh_secret.get_crypt_pk()?;
        let seeder_pk = intro_point.seeder_pk.clone();

        info!("Creating e2e circuit for infohash: {}", to_hex(&info_hash));

        let mut hop = Hop::new(intro_peer, HashSet::from([]));
        hop.dh_secret = Some(dh_secret);
        hop.dh_first_part = Some(dh_first_part.clone());

        let identifier = self.request_cache.generate_identifier() as u16;
        let cache = E2ERequestCache { info_hash: info_hash.clone(), hop, intro_point: intro_point.clone() };
        self.request_cache.add_identifier(
            "E2ERequestCache".to_owned(),
            identifier,
            Some(10),
            Some(Arc::new(cache)),
        );

        info!("Sending create-e2e to {}", intro_point.address);
        let response = CreateE2EPayload {
            circuit_id: circuit.circuit_id,
            identifier,
            info_hash: *info_hash,
            node_public_key: VarLenH { data_len: seeder_pk.len() as u16, data: seeder_pk },
            key: VarLenH { data_len: dh_first_part.len() as u16, data: dh_first_part },
        };
        self.rt.send_cell(&response, None).await?;
        Ok(())
    }

    pub async fn on_create_e2e(
        &self,
        source_address: SocketAddr,
        circuit_id: u32,
        cell: &mut Vec<u8>,
    ) -> Result<()> {
        let mut payload: CreateE2EPayload = unpack_cell_payload(cell)?;
        let node_pk = payload.node_public_key.data.clone();
        let infohash = payload.info_hash.clone();

        // If we don't have a circuit, we need to forward the message
        if !self.rt.circuits.load().contains_key(&circuit_id) {
            if let Some(entry) = self.hs_state.intro_point_for.get(&node_pk) {
                info!("On create-e2e: forwarding message because received over socket");
                let (exit, _) = entry.value();

                // We use (address, request_id) for tracking the handshake.
                self.hs_state.introduction_bridges.insert((exit.circuit_id, payload.identifier), circuit_id);

                payload.circuit_id = exit.circuit_id;
                let _ = self.rt.send_cell(&payload, None).await;
            } else {
                info!("On create-e2e: dropping message for unknown seeder key: {}", to_hex(&node_pk));
            }
            return Ok(());
        }

        info!("On create-e2e: creating rendezvous point");
        let swarms = self.hs_state.swarms.load();
        let is_seeding =
            swarms.get(&infohash).map(|swarm| swarm.seeding.load(Ordering::Relaxed)).unwrap_or(false);

        if !is_seeding {
            warn!("On create-e2e: not seeding");
            return Ok(());
        }

        if let Ok(rp) = self.create_rendezvous_point(&infohash).await {
            let community_clone = self.self_handle.get().unwrap().clone();
            tokio::spawn(async move {
                match rp.address.result_timeout(Duration::from_secs(30)).await {
                    Ok(client_address) => {
                        info!("On create-e2e: rendezvous point is ready at {:?}", client_address);
                        let _ =
                            community_clone.create_created_e2e(rp, source_address, payload, circuit_id).await;
                    }
                    Err(_) => {
                        warn!("On create-e2e: rendezvous point timed out");
                        community_clone.rt.remove_circuit(rp.circuit.circuit_id);
                        // TODO: FIX THE CLEANUP
                        // community_clone.hs_state.rendezvous_point_for.remove(&rp.circuit.circuit_id);
                    }
                }
            });
        }
        Ok(())
    }

    pub async fn tunnel_data(
        &self,
        circuit_id: u32,
        destination: SocketAddr,
        payload: Vec<u8>,
    ) -> Result<()> {
        let is_exit = self.rt.exits.load().get(&circuit_id).is_some();
        let unspecified = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let mut prefixed_payload = Vec::with_capacity(22 + payload.len());
        prefixed_payload.extend_from_slice(&self.rt.settings.load().prefix);
        prefixed_payload.extend_from_slice(&payload);
        let data_payload = DataPayload {
            circuit_id,
            dest_address: (if is_exit { unspecified } else { destination }).into(),
            org_address: (if is_exit { destination } else { unspecified }).into(),
            data: Raw { data: prefixed_payload },
        };
        match self.rt.send_cell(&data_payload, None).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub async fn create_created_e2e(
        &self,
        rp: Arc<RendezvousPoint>,
        _source_address: SocketAddr,
        payload: CreateE2EPayload,
        circuit_id: u32,
    ) -> Result<()> {
        let swarms = self.hs_state.swarms.load();
        let Some(swarm) = swarms.get(&payload.info_hash) else {
            return Err("swarm doesn't exist".to_owned());
        };

        let seeder_sk = swarm.seeder_sk.as_ref().ok_or_else(|| "no seeder_sk for swarm".to_owned())?;
        let (crypt_pk, auth, session_keys) = SessionKeys::generate_inbound(seeder_sk, &payload.key.data)?;

        let hops_guard = rp.circuit.hops.load();
        let addr = rp.address.result().await;
        let hop = hops_guard.verified.last().ok_or_else(|| "no rendezvous hop".to_owned())?;
        let key = hop.public_key_bin();
        let rp_info = RendezvousInfo {
            address: addr,
            key: VarLenH { data_len: key.len() as u16, data: key },
            cookie: rp.cookie.clone(),
        };
        let mut rp_info_bytes = rp_info.to_bytes().map_err(|_| "error encoding RendezvousInfo".to_owned())?;
        let Ok(_) = session_keys.encrypt_in_place(&mut rp_info_bytes, Direction::Forward) else {
            return Err("error encrypting RendezvousInfo".to_owned());
        };

        let auth_fixed: [u8; 32] =
            auth.as_slice()[..32].try_into().map_err(|e| format!("bad auth size: {e}"))?;

        rp.circuit.hs_keys.store(std::sync::Arc::new(vec![session_keys.clone()]));
        let response = CreatedE2EPayload {
            circuit_id,
            identifier: payload.identifier,
            key: VarLenH { data_len: crypt_pk.len() as u16, data: crypt_pk },
            auth: auth_fixed,
            rp_info_enc: Raw { data: rp_info_bytes },
        };

        info!("Sending created-e2e for {} to {}", rp.circuit.circuit_id, circuit_id);
        self.rt.send_cell(&response, None).await?;
        Ok(())
    }

    pub async fn on_created_e2e(
        &self,
        source_address: SocketAddr,
        circuit_id: u32,
        cell: &mut Vec<u8>,
    ) -> Result<()> {
        let mut payload: CreatedE2EPayload = unpack_cell_payload(cell)?;

        // If we don't have a circuit, we need to forward the message
        if !self.rt.circuits.load().contains_key(&circuit_id) {
            if let Some(target_cid_ref) =
                self.hs_state.introduction_bridges.get(&(circuit_id, payload.identifier))
            {
                info!("On create-e2e: forwarding message because received over socket");
                payload.circuit_id = *target_cid_ref;
                self.rt.send_cell(&payload, None).await?;
            } else {
                info!(
                    "On created-e2e: dropping message for unknown target: {}, {}",
                    source_address, payload.identifier
                );
            }
            return Ok(());
        }

        let cache = match self.request_cache.pop("E2ERequestCache", payload.identifier) {
            CacheResult::Identifier(Some(raw_data)) => raw_data
                .downcast::<E2ERequestCache>()
                .map_err(|_| "failed to get E2ERequestCache data".to_owned())?,
            _ => {
                warn!("Unexpected create-e2e: {}", payload.identifier);
                return Ok(());
            }
        };

        let seeder_public_key = PublicKey::from_bytes(&cache.intro_point.seeder_pk)
            .map_err(|e| format!("Invalid seeder_pk: {e}"))?;
        let seeder_identity_crypt_pk =
            seeder_public_key.get_crypt_pk().map_err(|_| "failed to get seeder crypt_pk".to_owned())?;

        let session_keys = match SessionKeys::verify_outbound(
            &cache.hop.dh_secret.clone().ok_or_else(|| "No dh_secret")?,
            &seeder_identity_crypt_pk,
            &payload.key.data,
            &payload.auth,
        ) {
            Ok(keys) => keys,
            Err(e) => {
                return Err(format!("E2E DH verification failed: {}", e));
            }
        };

        let mut rp_info_bytes = payload.rp_info_enc.data.clone();
        session_keys
            .decrypt_in_place(&mut rp_info_bytes, Direction::Forward)
            .map_err(|e| format!("failed decrypting RendezvousInfo: {e}"))?;

        let (_, rp_info) = RendezvousInfo::from_bytes((&rp_info_bytes, 0))
            .map_err(|e| format!("error decoding RendezvousInfo: {e}").to_owned())?;

        info!(
            "Got created-e2e from {:?}. Targeting rendezvous address: {:?}",
            source_address, rp_info.address
        );

        let required_exit = Peer {
            address: match rp_info.address {
                Address::V4(addr_v4) => std::net::SocketAddr::V4(addr_v4),
                Address::V6(addr_v6) => std::net::SocketAddr::V6(addr_v6),
                Address::DomainAddress(_, _) => return Err(format!("unsupported address").into()),
            },
            public_key: PublicKey::from_bytes(&rp_info.key.data).map_err(|e| format!("{e}"))?,
            private_key: None,
        };
        let circuit = self
            .create_circuit_for_infohash(
                &cache.info_hash,
                CircuitType::RPDownloader,
                None,
                Some(required_exit),
            )
            .await?;
        let identifier = self.request_cache.generate_identifier() as u16;
        self.request_cache.add_identifier(
            "LinkRequestCache".to_owned(),
            identifier,
            Some(10),
            Some(Arc::new(LinkRequestCache {
                circuit: circuit.clone(),
                info_hash: cache.info_hash.clone(),
                session_keys: Arc::new(session_keys),
            })),
        );

        let response = LinkE2EPayload { circuit_id: circuit.circuit_id, identifier, cookie: rp_info.cookie };

        if let Some(swarm) = self.hs_state.swarms.load().get(&cache.info_hash) {
            swarm.add_connection(circuit.clone(), cache.intro_point.clone());
        }

        self.hs_state
            .swarms
            .load()
            .get(&cache.info_hash)
            .ok_or_else(|| "swarm doesn't exist".to_owned())?
            .add_connection(circuit.clone(), cache.intro_point.clone());

        self.rt.send_cell(&response, None).await?;
        Ok(())
    }

    pub async fn on_link_e2e(
        &self,
        _source_address: SocketAddr,
        circuit_id: u32,
        cell: &mut Vec<u8>,
    ) -> Result<()> {
        let payload: LinkE2EPayload = unpack_cell_payload(cell)?;
        let cookie_bytes = payload.cookie.clone();

        let Some(entry) = self.hs_state.rendezvous_point_for.get(&cookie_bytes) else {
            warn!("Not a rendezvous point for cookie: {}", to_hex(&cookie_bytes));
            return Ok(());
        };

        let exit_sd = entry.value();
        if exit_sd.is_enabled() {
            warn!("Seeder exit socket {} is enabled, cannot link", exit_sd.circuit_id);
            return Ok(());
        };

        let exits = self.rt.exits.load();
        let Some(exit_dl) = exits.get(&circuit_id) else {
            return Err("cannot find exits".to_owned());
        };
        if exit_dl.is_enabled() {
            warn!("Downloader exit socket {} is enabled, cannot link", exit_dl.circuit_id);
            return Ok(());
        }

        info!("Linking downloader {} and seeder {}", exit_dl.circuit_id, exit_sd.circuit_id);

        let response = LinkedE2EPayload { circuit_id: exit_dl.circuit_id, identifier: payload.identifier };
        self.rt.send_cell(&response, Some(exit_dl.peer)).await?;

        _ = self.rt.remove_exit(exit_dl.circuit_id);
        _ = self.rt.remove_exit(exit_sd.circuit_id);

        let rv_bridge = Arc::new(Rendezvous::new(
            exit_dl.circuit_id,
            exit_dl.peer.clone(),
            exit_dl.keys.load().to_vec(),
            exit_sd.circuit_id,
            exit_sd.peer.clone(),
            exit_sd.keys.load().to_vec(),
        ));

        self.rt.rendezvous.rcu(|active_map| {
            let mut new_map = (**active_map).clone();
            new_map.insert(exit_dl.circuit_id, rv_bridge.clone());
            new_map.insert(exit_sd.circuit_id, rv_bridge.clone());
            new_map
        });

        Ok(())
    }

    pub async fn on_linked_e2e(
        &self,
        source_address: SocketAddr,
        _circuit_id: u32,
        cell: &mut Vec<u8>,
    ) -> Result<()> {
        let payload: LinkedE2EPayload = unpack_cell_payload(cell)?;

        let cache = match self.request_cache.pop("LinkRequestCache", payload.identifier) {
            CacheResult::Identifier(Some(raw_data)) => raw_data
                .downcast::<LinkRequestCache>()
                .map_err(|_| "failed to get LinkRequestCache data".to_owned())?,
            _ => {
                warn!("Unexpected linked-e2e identifier: {}", payload.identifier);
                return Ok(());
            }
        };

        info!("Got linked-e2e from: {:?}", source_address);

        let circuit = &cache.circuit;
        circuit.hs_keys.store(std::sync::Arc::new(vec![(*cache.session_keys).clone()]));

        let virtual_ip: IpAddr = circuit_id_to_ip(circuit.circuit_id).into();
        let virtual_port: u16 = 1024;

        if let Err(e) = self.hs_state.call_e2e_callback(&cache.info_hash, virtual_ip, virtual_port) {
            error!("failed to call e2e_callback: {}", e);
        }

        Ok(())
    }

    pub async fn start_ip_announce(&self, info_hash: [u8; 20]) -> Result<()> {
        let dht_guard = self.hs_state.dht.load();
        let Some(dht_handle) = dht_guard.as_ref() else {
            return Err("DHT not running".to_owned());
        };

        info!("Start announcing introduction point for {}...", to_hex(&info_hash));

        match dht_handle.lookup(info_hash).await {
            Ok(result) => {
                info!("Got {} closer nodes and {} seeders from DHT", result.nodes.len(), result.values.len());
            }
            Err(e) => {
                warn!("DHT lookup failed: {}", e);
            }
        }

        dht_handle.start_announce(info_hash, None);
        Ok(())
    }

    pub fn stop_ip_announce(&self, info_hash: &[u8; 20]) -> bool {
        if let Some(dht_handle) = self.hs_state.dht.load().as_ref() {
            info!("Stop announcing introduction point for {}", to_hex(&info_hash));
            return dht_handle.stop_announce(info_hash);
        }
        false
    }

    pub async fn request_ip_lookup(&self, info_hash: &[u8; 20]) -> Result<()>
    where
        <IPResponse as bencode::FromBencode>::Err: std::fmt::Debug,
    {
        info!("Performing introduction point lookup for swarm {}...", to_hex(info_hash));

        let dht_guard = self.hs_state.dht.load();
        let Some(dht_handle) = dht_guard.as_ref() else {
            return Err("DHT not running".to_owned());
        };

        let owned_info_hash: [u8; 20] = *info_hash;
        let results = match dht_handle.lookup(owned_info_hash).await {
            Ok(result) => {
                info!("Discovered {} target peers", result.nodes.len());
                result
            }
            Err(e) => return Err(format!("Failed to do DHT lookup: {}", e)),
        };

        let tunnels = self.self_handle.get().expect("Self handle uninitialized").clone();
        let swarms_guard = tunnels.hs_state.swarms.load();
        let Some(swarm) = swarms_guard.get(&owned_info_hash) else {
            return Err(format!("Failed to do DHT lookup: unknown swarm {}", to_hex(&owned_info_hash)));
        };
        if results.values.is_empty() {
            info!("Failed to do DHT lookup: no introduction points");
            return Ok(());
        }

        info!("Got {} introduction point addresses. Requesting keys...", results.values.len());

        for intro_addr in results.values {
            let dht_client = Arc::clone(dht_handle);
            let swarm_arc = Arc::clone(swarm);
            let task_name = format!("get_ips_{}_{}", to_hex(owned_info_hash), intro_addr.port());
            let tunnels_clone = tunnels.clone();

            self.rt.task_manager.spawn(&task_name, async move {
                let request_payload =
                    IPRequest { id: dht_client.dht_discover.node_id, info_hash: owned_info_hash };

                match dht_client.dht_discover.send_query(request_payload, intro_addr).await {
                    Ok(ip_response) => {
                        if let Some(ips) = ip_response.peers {
                            info!("Got {} introduction points from {}", ips.len(), intro_addr);

                            for ip in ips {
                                swarm_arc.add_intro_point(ip.clone());
                                if !swarm_arc.has_connection(&ip.seeder_pk) {
                                    if let Err(e) = tunnels_clone.create_e2e(&owned_info_hash, ip).await {
                                        trace!("Auto-e2e bootstrap cell dispatch failed: {e}");
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to get introduction info from {}: {}", intro_addr, e);
                    }
                }
            });
        }

        Ok(())
    }

    pub fn response_ip_lookup(&self) -> Result<()> {
        let tunnels = self.self_handle.get().expect("Self handle uninitialized").clone();

        self.rt.task_manager.spawn("community_discover_extensions", async move {
            let dht_guard = tunnels.hs_state.dht.load();
            let Some(dht) = dht_guard.as_ref() else {
                error!("DHT not running");
                return;
            };

            let dht_announce = Arc::clone(&dht.dht_announce);
            let dht_rx = dht_announce.extensions_rx.clone();

            let my_wan = match tunnels.rt.runtime.my_estimated_wan.load().clone() {
                Some(addr) => *addr,
                None => {
                    error!("Failed to respond to get_ips: my_estimated_wan not set");
                    return;
                }
            };
            let my_pk = tunnels.rt.runtime.get_my_public_key().clone();

            while let Ok(query) = dht_rx.recv_async().await {
                if query.method == b"get_ips" {
                    let args_bencode = bencode::Bencode::Dict(query.args);
                    let Ok(req) = IPRequest::from_bencode(&args_bencode) else {
                        continue;
                    };

                    let mut intro_points = Vec::new();
                    for entry in tunnels.hs_state.intro_point_for.iter() {
                        let seeder_pk = entry.key();
                        let (_, info_hash) = entry.value();

                        if *info_hash == req.info_hash {
                            let ip =
                                IntroductionPoint::new(my_wan, my_pk.clone(), seeder_pk.clone(), 1, None);
                            intro_points.push(ip);
                        }
                    }
                    let response = IPResponse {
                        id: dht_announce.node_id,
                        info_hash: req.info_hash,
                        peers: Some(intro_points),
                    };

                    let _ = dht_announce.send_response(response, query.transaction_id, query.origin).await;
                }
            }
        });
        Ok(())
    }
}

#[pyclass(get_all, from_py_object)]
#[derive(Clone)]
pub struct PySwarm {
    pub info_hash: [u8; 20],
    pub num_intro_points: usize,
    pub num_seeders: usize,
    pub num_connections: usize,
    pub num_connections_incomplete: usize,
    pub seeding: bool,
    pub last_lookup: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
}
