use std::net::SocketAddr;
use std::sync::atomic::AtomicU8;

use arc_swap::ArcSwap;
use pyo3::pyclass;

use crate::community::serialization::CellPayload;
use crate::crypto::cipher::{Direction, SessionKeys};
use crate::transport::stats::AtomicStat;
use crate::util;

#[derive(Debug)]
pub struct Relay {
    pub circuit_id_fw: u32,
    pub peer_fw: SocketAddr,

    pub circuit_id_bw: u32,
    pub peer_bw: SocketAddr,

    pub rendezvous_relay: bool,
    pub keys: ArcSwap<Vec<SessionKeys>>,
    pub relay_early_left: AtomicU8,
    pub stats: AtomicStat,
    pub creation_time: u64,
}

impl Relay {
    pub fn new(
        circuit_id_fw: u32,
        peer_fw: SocketAddr,
        circuit_id_bw: u32,
        peer_bw: SocketAddr,
        max_relay_early: u8,
    ) -> Self {
        Relay {
            circuit_id_fw,
            peer_fw,
            circuit_id_bw,
            peer_bw,
            rendezvous_relay: false,
            keys: ArcSwap::from_pointee(Vec::new()),
            stats: AtomicStat::default(),
            relay_early_left: AtomicU8::new(max_relay_early),
            creation_time: util::get_time(),
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

    pub fn apply_layer(
        &self,
        cell: &mut CellPayload,
        is_inbound: bool,
        circuit_id: u32,
    ) -> Result<(), String> {
        if is_inbound {
            if circuit_id == self.circuit_id_fw {
                self.add_layer(cell)?;
            } else {
                self.remove_layer(cell)?;
            }
        } else {
            if circuit_id == self.circuit_id_bw {
                self.add_layer(cell)?;
            } else {
                self.remove_layer(cell)?;
            }
        }

        Ok(())
    }

    pub fn process(
        &self,
        cell: &mut CellPayload,
        is_inbound: bool,
        circuit_id: u32,
    ) -> Result<Option<SocketAddr>, String> {
        if is_inbound {
            self.stats.add_down(cell.len(), util::get_time());

            if circuit_id == self.circuit_id_fw {
                cell.swap_circuit_id(self.circuit_id_bw);
                Ok(Some(self.peer_bw))
            } else {
                let current_left = self.relay_early_left.load(std::sync::atomic::Ordering::Relaxed);
                cell.check(current_left, false)?;

                if cell.is_relay_early() {
                    self.relay_early_left.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                }

                cell.swap_circuit_id(self.circuit_id_fw);
                Ok(Some(self.peer_fw))
            }
        } else {
            self.stats.add_down(cell.len(), util::get_time());

            if circuit_id == self.circuit_id_bw {
                Ok(Some(self.peer_bw))
            } else {
                Ok(Some(self.peer_fw))
            }
        }
    }
}

#[pyclass(get_all, from_py_object)]
#[derive(Clone)]
pub struct PyRelayStats {
    pub circuit_id_fw: u32,
    pub circuit_id_bw: u32,
    pub is_rendezvous: bool,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub creation_time: u64,
}
