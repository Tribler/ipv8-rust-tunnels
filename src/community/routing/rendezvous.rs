use std::net::SocketAddr;

use arc_swap::ArcSwap;
use pyo3::pyclass;

use crate::community::serialization::CellPayload;
use crate::crypto::cipher::{Direction, SessionKeys};
use crate::transport::stats::AtomicStat;
use crate::util;

#[derive(Debug)]
pub struct Rendezvous {
    pub circuit_id_dl: u32,
    pub peer_dl: SocketAddr,
    pub keys_dl: ArcSwap<Vec<SessionKeys>>,

    pub circuit_id_sd: u32,
    pub peer_sd: SocketAddr,
    pub keys_sd: ArcSwap<Vec<SessionKeys>>,

    pub stats: AtomicStat,
    pub creation_time: u64,
}

impl Rendezvous {
    pub fn new(
        circuit_id_dl: u32,
        peer_dl: SocketAddr,
        keys_dl: Vec<SessionKeys>,
        circuit_id_sd: u32,
        peer_sd: SocketAddr,
        keys_sd: Vec<SessionKeys>,
    ) -> Self {
        Self {
            circuit_id_dl,
            peer_dl,
            keys_dl: ArcSwap::from_pointee(keys_dl),
            circuit_id_sd,
            peer_sd,
            keys_sd: ArcSwap::from_pointee(keys_sd),
            stats: AtomicStat::default(),
            creation_time: util::get_time(),
        }
    }

    pub fn add_layer(&self, cell: &mut CellPayload, circuit_id: u32) -> Result<(), String> {
        if circuit_id == self.circuit_id_dl {
            cell.encrypt(Direction::Backward, &self.keys_sd.load())?;
        } else {
            cell.encrypt(Direction::Backward, &self.keys_dl.load())?;
        }
        Ok(())
    }

    pub fn remove_layer(&self, cell: &mut CellPayload, circuit_id: u32) -> Result<(), String> {
        if circuit_id == self.circuit_id_dl {
            cell.decrypt(Direction::Forward, &self.keys_dl.load())?;
        } else {
            cell.decrypt(Direction::Forward, &self.keys_sd.load())?;
        }
        Ok(())
    }

    pub fn apply_layer(
        &self,
        cell: &mut CellPayload,
        is_inbound: bool,
        circuit_id: u32,
    ) -> Result<(), String> {
        if is_inbound {
            self.remove_layer(cell, circuit_id)?;
        }
        self.add_layer(cell, circuit_id)?;
        Ok(())
    }

    pub fn process(
        &self,
        cell: &mut CellPayload,
        is_inbound: bool,
        circuit_id: u32,
    ) -> Result<Option<SocketAddr>, String> {
        let (target_peer, target_circuit_id, is_downlink) = if circuit_id == self.circuit_id_dl {
            (self.peer_sd, self.circuit_id_sd, true)
        } else {
            (self.peer_dl, self.circuit_id_dl, false)
        };

        if is_downlink {
            self.stats.add_up(cell.len());
        } else {
            self.stats.add_down(cell.len(), util::get_time());
        }

        if is_inbound {
            cell.swap_circuit_id(target_circuit_id);
        }

        Ok(Some(target_peer))
    }
}

#[pyclass(get_all, from_py_object)]
#[derive(Clone)]
pub struct PyRendezvousStats {
    pub circuit_id_dl: u32,
    pub circuit_id_sd: u32,
    pub peer_dl: String,
    pub peer_sd: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub creation_time: u64,
}
