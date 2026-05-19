use std::hash::Hash;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::keys::{PrivateKey, PublicKey};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Peer {
    pub address: SocketAddr,
    pub public_key: PublicKey,
    pub private_key: Option<PrivateKey>,
}

impl Peer {
    pub fn mid(&self) -> [u8; 20] {
        self.public_key.key_to_hash().unwrap_or([0u8; 20])
    }
}

#[derive(Debug, Clone)]
pub struct CachedNode<M> {
    pub peer: Peer,
    pub metadata: M,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Default)]
pub struct PeerCache<M> {
    pub entries: Arc<Mutex<Vec<CachedNode<M>>>>,
}

impl<M: Clone> PeerCache<M> {
    pub fn new() -> Self {
        Self { entries: Arc::new(Mutex::new(Vec::new())) }
    }

    pub fn add(&self, peer: Peer, metadata: M) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut lock = self.entries.lock().unwrap();

        if let Some(existing) = lock.iter_mut().find(|n| n.peer.mid() == peer.mid()) {
            existing.peer.address = peer.address;
            existing.last_seen = now;
            existing.metadata = metadata;
        } else {
            lock.push(CachedNode { peer, metadata, last_seen: now });
        }
    }

    pub fn get_by_socketaddr(&self, addr: &SocketAddr) -> Option<CachedNode<M>> {
        let lock = self.entries.lock().unwrap();
        lock.iter().find(|node| &node.peer.address == addr).cloned()
    }

    pub fn get_by_mid(&self, mid: &[u8]) -> Option<CachedNode<M>> {
        let lock = self.entries.lock().unwrap();
        lock.iter().find(|node| node.peer.mid() == mid).cloned()
    }

    pub fn get_by_public_key_bin(&self, key_bytes: &[u8]) -> Option<CachedNode<M>> {
        let lock = self.entries.lock().unwrap();
        lock.iter()
            .find(|node| node.peer.public_key.key_to_bin().map(|bin| bin == key_bytes).unwrap_or(false))
            .cloned()
    }

    pub fn replace_snapshot(&self, new_entries: Vec<CachedNode<M>>) {
        let mut lock = self.entries.lock().unwrap();
        *lock = new_entries;
    }

    pub fn prune_old_nodes(&self, max_age_secs: u64) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut lock = self.entries.lock().unwrap();
        lock.retain(|node| now - node.last_seen < max_age_secs);
    }
}
