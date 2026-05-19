use std::collections::HashSet;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::vec;

use arc_swap::{ArcSwap, ArcSwapOption};
use pyo3::pyclass;
use tokio::net::UdpSocket;

use crate::community::routing::peer::PeerFlag;
use crate::community::serialization::{CellId, CellPayload};
use crate::crypto::cipher::{Direction, SessionKeys};
use crate::crypto::keys::{PrivateKey, PublicKey};
use crate::peer::Peer;
use crate::transport::stats::AtomicStat;
use crate::util::{self, Future};

#[pyclass(eq)]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum CircuitType {
    Data,
    IPSeeder,
    IPDownloader,
    RPSeeder,
    RPDownloader,
}

impl fmt::Display for CircuitType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[pyclass(eq)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Ready,
    Extending,
    Closing,
}

impl fmt::Display for CircuitState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone)]
pub struct Hop {
    pub peer: Peer,
    pub flags: HashSet<PeerFlag>,
    pub dh_first_part: Option<Vec<u8>>,
    pub dh_secret: Option<PrivateKey>,
}

impl Hop {
    pub fn new(peer: Peer, flags: HashSet<PeerFlag>) -> Self {
        Hop { peer, flags, dh_first_part: None, dh_secret: None }
    }

    pub fn address(&self) -> &SocketAddr {
        &self.peer.address
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.peer.public_key
    }

    pub fn public_key_bin(&self) -> Vec<u8> {
        self.peer.public_key.key_to_bin().unwrap_or_default()
    }

    pub fn mid(&self) -> [u8; 20] {
        self.peer.mid()
    }
}

#[derive(Debug, Clone)]
pub struct Hops {
    pub verified: Vec<Hop>,
    pub unverified: Option<Hop>,
}

#[derive(Debug)]
pub struct Circuit {
    pub circuit_id: u32,
    pub goal_hops: u8,
    pub circuit_type: CircuitType,
    pub peer: SocketAddr,
    pub socket: ArcSwapOption<UdpSocket>,
    pub creation_time: u64,
    pub infohash: Option<Vec<u8>>,

    pub hops: ArcSwap<Hops>,

    pub keys: ArcSwap<Vec<SessionKeys>>,
    pub hs_keys: ArcSwap<Vec<SessionKeys>>,

    pub relay_early_left: AtomicU8,
    pub closing: AtomicBool,
    pub required_exit: Option<Peer>,

    pub stats: AtomicStat,

    pub ready: Future<Result<(), String>>,
}

impl Circuit {
    pub fn new(
        circuit_id: u32,
        goal_hops: u8,
        ctype: CircuitType,
        peer: SocketAddr,
        max_relay_early: u8,
    ) -> Self {
        Circuit {
            circuit_id,
            goal_hops: goal_hops,
            circuit_type: ctype,
            peer: peer,
            socket: ArcSwapOption::empty(),
            creation_time: util::get_time(),
            infohash: None,
            hops: ArcSwap::from_pointee(Hops { verified: vec![], unverified: None }),
            keys: ArcSwap::from_pointee(vec![]),
            hs_keys: ArcSwap::from_pointee(vec![]),
            relay_early_left: AtomicU8::new(max_relay_early),
            closing: AtomicBool::new(false),
            required_exit: None,
            stats: AtomicStat::default(),
            ready: Future::new(),
        }
    }

    pub fn state(&self) -> CircuitState {
        if self.closing.load(Ordering::Relaxed) {
            return CircuitState::Closing;
        }

        if self.hops.load().verified.len() < self.goal_hops as usize {
            return CircuitState::Extending;
        }
        CircuitState::Ready
    }

    pub fn first_hop(&self) -> Option<Hop> {
        let hops = self.hops.load();
        hops.verified.first().cloned().or_else(|| hops.unverified.clone())
    }

    pub fn last_hop(&self) -> Option<Hop> {
        self.hops.load().verified.last().cloned()
    }

    pub fn exit_flags(&self) -> Vec<u16> {
        self.hops
            .load()
            .verified
            .last()
            .map(|last_hop| last_hop.flags.iter().map(|&f| f as u16).collect())
            .unwrap_or_default()
    }

    pub fn has_exit_flag(&self, flag: &PeerFlag) -> bool {
        self.hops.load().verified.last().map(|last_hop| last_hop.flags.contains(flag)).unwrap_or(false)
    }

    pub fn set_unverified_hop(&self, hop: Hop) {
        self.hops.store(Arc::new(Hops { verified: vec![], unverified: Some(hop) }));
    }

    pub fn clear_unverified_hop(&self) {
        let old = self.hops.load();
        self.hops.store(Arc::new(Hops { verified: old.verified.clone(), unverified: None }));
    }

    pub fn data_ready(&self) -> bool {
        if self.circuit_type != CircuitType::Data {
            return false;
        }

        let current_keys_count = self.keys.load().len();
        current_keys_count == self.goal_hops as usize
    }

    pub fn is_e2e(&self) -> bool {
        !self.hs_keys.load().is_empty()
    }

    pub fn append_hop(&self, session_keys: SessionKeys, hop: Hop) -> usize {
        let mut new_keys = (**self.keys.load()).clone();
        new_keys.push(session_keys);
        self.keys.store(std::sync::Arc::new(new_keys));

        let old_hops = self.hops.load();
        let mut new_verified = old_hops.verified.clone();
        new_verified.push(hop);
        let hop_count = new_verified.len();

        self.hops.store(std::sync::Arc::new(Hops { verified: new_verified, unverified: None }));
        hop_count
    }

    pub fn add_all_layers(&self, cell: &mut CellPayload) -> Result<(), String> {
        if self.is_e2e() {
            let direction = if self.circuit_type == CircuitType::RPSeeder {
                Direction::Forward
            } else {
                Direction::Backward
            };
            cell.encrypt(direction, &self.hs_keys.load())?;
        }
        cell.encrypt(Direction::Forward, &self.keys.load())?;
        Ok(())
    }

    pub fn remove_all_layers(&self, cell: &mut CellPayload) -> Result<(), String> {
        cell.decrypt(Direction::Backward, &self.keys.load())?;
        if self.is_e2e() {
            let direction = if self.circuit_type == CircuitType::RPDownloader {
                Direction::Forward
            } else {
                Direction::Backward
            };
            cell.decrypt(direction, &self.hs_keys.load())?;
        }
        Ok(())
    }

    pub fn process(&self, cell: &mut CellPayload, is_inbound: bool) -> Result<Option<SocketAddr>, String> {
        let current_left = self.relay_early_left.load(std::sync::atomic::Ordering::Relaxed);

        if is_inbound {
            cell.check(current_left, false)?;
            self.stats.add_down(cell.len(), util::get_time());
        } else {
            self.stats.add_up(cell.len());

            if cell.cell_id() == (CellId::Extend) as u8 {
                self.relay_early_left.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                cell.set_relay_early(true);
            } else if current_left > 0 {
                cell.set_relay_early(true);
                self.relay_early_left.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            } else {
                cell.set_relay_early(false);
            }
        }
        Ok(Some(self.peer))
    }
}

#[pyclass(get_all)]
#[derive(Clone)]
pub struct PyHopStats {
    pub address: String,
    pub mid: Vec<u8>,
    pub public_key: Vec<u8>,
    pub is_verified: bool,
    pub flags: Vec<u16>,
}

#[pyclass(get_all)]
#[derive(Clone)]
pub struct PyCircuitStats {
    pub circuit_id: u32,
    pub goal_hops: u8,
    pub peer: String,
    pub creation_time: u64,
    pub state: String,
    pub circuit_type: String,
    pub data_ready: bool,
    pub hops: Vec<PyHopStats>,
    pub exit_flags: Vec<u16>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub last_received: u64,
}
