use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Node {
    pub id: [u8; 20],
    pub address: SocketAddr,
    pub last_seen: Instant,
}

impl Node {
    #[inline(always)]
    pub fn distance_to(&self, target: &[u8; 20]) -> [u8; 20] {
        let mut dist = [0u8; 20];
        for i in 0..20 {
            dist[i] = self.id[i] ^ target[i];
        }
        dist
    }
}

pub struct Nodes {
    pub local_id: [u8; 20],
    pub entries: Mutex<Vec<Node>>,
}

impl Nodes {
    pub fn new(local_id: [u8; 20], max_nodes: usize) -> Self {
        Self { local_id, entries: Mutex::new(Vec::with_capacity(max_nodes)) }
    }

    pub fn update(&self, id: [u8; 20], address: SocketAddr) {
        let mut guard = self.entries.lock().unwrap();

        if let Some(existing) = guard.iter_mut().find(|n| n.id == id) {
            existing.address = address;
            existing.last_seen = Instant::now();
            return;
        }

        if guard.len() < guard.capacity() {
            guard.push(Node { id, address, last_seen: Instant::now() });
            return;
        }

        if let Some((idx, _)) = guard.iter().enumerate().min_by_key(|(_, n)| n.last_seen) {
            guard[idx] = Node { id, address, last_seen: Instant::now() };
        }
    }

    pub fn find_closest(&self, target: [u8; 20], count: usize) -> Vec<Node> {
        let guard = self.entries.lock().unwrap();
        let mut list = guard.clone();
        drop(guard);

        list.sort_by_cached_key(|node| node.distance_to(&target));
        list.truncate(count);
        list
    }

    pub fn get_all(&self) -> Vec<Node> {
        self.entries.lock().unwrap().clone()
    }
}

#[derive(Debug, Clone)]
pub struct PeerValue {
    pub address: SocketAddr,
    pub expires_at: Instant,
}

pub struct Values {
    pub swarms: Mutex<HashMap<[u8; 20], Vec<PeerValue>>>,
    pub ttl: Duration,
    pub max_entries: usize,
}

impl Values {
    pub fn new(ttl_minutes: u64, max_entries: usize) -> Self {
        Self { swarms: Mutex::new(HashMap::new()), ttl: Duration::from_secs(ttl_minutes * 60), max_entries }
    }

    pub fn store_peer(&self, info_hash: [u8; 20], address: SocketAddr) {
        let mut guard = self.swarms.lock().unwrap();

        if !guard.contains_key(&info_hash) && guard.len() >= self.max_entries {
            if let Some(random_key) = guard.keys().next().copied() {
                guard.remove(&random_key);
            }
        }

        let list = guard.entry(info_hash).or_insert_with(Vec::new);
        let expires_at = Instant::now() + self.ttl;

        if let Some(existing) = list.iter_mut().find(|p| p.address == address) {
            existing.expires_at = expires_at;
            return;
        }

        list.push(PeerValue { address, expires_at });
    }

    pub fn get_peers(&self, info_hash: &[u8; 20]) -> Option<Vec<Vec<u8>>> {
        let mut guard = self.swarms.lock().unwrap();
        let list = guard.get_mut(info_hash)?;

        let now = Instant::now();
        list.retain(|p| p.expires_at > now);

        if list.is_empty() {
            guard.remove(info_hash);
            return None;
        }

        let compact_list = list
            .iter()
            .filter_map(|p| match p.address {
                SocketAddr::V4(addr_v4) => {
                    let mut bytes = Vec::with_capacity(6);
                    bytes.extend_from_slice(&addr_v4.ip().octets());
                    bytes.extend_from_slice(&addr_v4.port().to_be_bytes());
                    Some(bytes)
                }
                _ => None,
            })
            .collect();

        Some(compact_list)
    }
}
