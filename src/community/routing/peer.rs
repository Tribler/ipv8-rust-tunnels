use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::peer::{CachedNode, Peer, PeerCache as GenericPeerCache};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerFlag {
    Relay = 1,
    ExitBt = 2,
    ExitIpv8 = 4,
    SpeedTest = 8,
    ExitBackup = 16384,
    ExitHttp = 32768,
}

impl fmt::Display for PeerFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub type PeerCache = GenericPeerCache<HashSet<PeerFlag>>;

impl GenericPeerCache<HashSet<PeerFlag>> {
    pub fn peers(&self, required_flags: &HashSet<PeerFlag>) -> Vec<Peer> {
        let lock = self.entries.lock().unwrap();
        lock.iter()
            .filter(|node| required_flags.iter().all(|flag| node.metadata.contains(flag)))
            .map(|node| node.peer.clone())
            .collect()
    }

    pub fn nodes(&self, required_flags: &HashSet<PeerFlag>) -> Vec<CachedNode<HashSet<PeerFlag>>> {
        let lock = self.entries.lock().unwrap();
        lock.iter()
            .filter(|node| required_flags.iter().all(|flag| node.metadata.contains(flag)))
            .cloned()
            .collect()
    }

    pub fn get_flags(&self, peer: &Peer) -> Option<HashSet<PeerFlag>> {
        let lock = self.entries.lock().unwrap();
        lock.iter().find(|node| node.peer == *peer).map(|node| node.metadata.clone())
    }

    pub fn get_handshake_candidates(&self) -> (Vec<Vec<u8>>, HashMap<Vec<u8>, Peer>) {
        let mut relay_nodes = self.nodes(&HashSet::from([PeerFlag::Relay]));
        relay_nodes.retain(|n| !n.metadata.contains(&PeerFlag::ExitBt));
        relay_nodes.truncate(4);

        let mut exit_nodes = self.peers(&HashSet::from([PeerFlag::ExitBt, PeerFlag::Relay]));
        exit_nodes.truncate(4);

        // Note: The candidate list is split into relays and exits by duplicating
        // the first exit node twice as a boundary marker.
        let mut peers_list = exit_nodes;
        if !peers_list.is_empty() {
            peers_list.insert(0, peers_list[0].clone());
        }

        let mut peers_keys = Vec::with_capacity(8);
        let mut peers_dict = HashMap::with_capacity(8);

        for peer in relay_nodes.into_iter().map(|n| n.peer).chain(peers_list) {
            if let Ok(bin_key) = peer.public_key.key_to_bin() {
                peers_keys.push(bin_key.clone());
                peers_dict.insert(bin_key, peer);
            }
        }

        (peers_keys, peers_dict)
    }
}
