use std::net::{Ipv4Addr, SocketAddr};

use crate::{
    crypto::{Direction, SessionKeys},
    payload, util,
};

#[derive(Debug)]
pub struct RelayRoute {
    pub circuit_id: u32,
    pub peer: SocketAddr,
    pub keys: Vec<SessionKeys>,
    pub direction: Direction,
    pub rendezvous_relay: bool,
    pub relay_early_count: u8,
    pub bytes_up: u32,
    pub bytes_down: u32,
    pub last_activity: u64,
}

impl RelayRoute {
    pub fn new(circuit_id: u32) -> Self {
        RelayRoute {
            circuit_id,
            peer: SocketAddr::from((Ipv4Addr::from(0), 0)),
            keys: Vec::new(),
            direction: Direction::Forward,
            rendezvous_relay: false,
            // Since the creation of a RelayRoute object is triggered by an extend (which was
            // wrapped in a cell that had the early_relay flag set) we start the count at 1.
            relay_early_count: 1,
            bytes_up: 0,
            bytes_down: 0,
            last_activity: 0,
        }
    }

    pub fn encrypt_outgoing_cell(&mut self, packet: Vec<u8>) -> Result<Vec<u8>, String> {
        // For non-rendezvous relays, this is required for sending an extended message.
        let direction = if self.rendezvous_relay { Direction::Backward } else { self.direction };
        let encrypted_cell = payload::encrypt_cell(&packet, direction, &mut self.keys)?;
        self.bytes_up += encrypted_cell.len() as u32;
        Ok(encrypted_cell)
    }

    pub fn convert_incoming_cell(
        &mut self,
        packet: &[u8],
        max_relay_early: u8,
    ) -> Result<Vec<u8>, String> {
        self.bytes_down += packet.len() as u32;
        self.last_activity = util::get_time();

        if packet[27] != 0 {
            return Err("Dropping cell (cell not encrypted)".to_owned());
        }
        if packet[28] != 0 && self.relay_early_count >= max_relay_early {
            return Err("Dropping cell (too many relay_early cells)".to_owned());
        }

        self.relay_early_count += 1;

        let dec = match self.direction {
            Direction::Forward => payload::decrypt_cell(packet, Direction::Forward, &self.keys)?,
            Direction::Backward => packet.to_vec(),
        };
        let enc = match self.direction {
            Direction::Forward => dec,
            Direction::Backward => payload::encrypt_cell(&dec, Direction::Backward, &mut self.keys)?,
        };
        Ok(payload::swap_circuit_id(&enc, self.circuit_id))
    }
}
