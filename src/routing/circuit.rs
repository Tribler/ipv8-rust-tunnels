use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
};

use deku::{DekuContainerWrite, DekuReader};
use tokio::net::UdpSocket;

use crate::{
    crypto::{Direction, SessionKeys},
    packet::{check_cell_flags, circuit_id_to_ip, decrypt_cell, encrypt_cell, unwrap_cell},
    payload::{self, Address},
    routing::exit::PeerFlag,
    util,
};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum CircuitType {
    Data,
    IPSeeder,
    RPSeeder,
    RPDownloader,
}

#[derive(Debug)]
pub struct Circuit {
    pub circuit_id: u32,
    pub peer: SocketAddr,
    pub keys: Vec<SessionKeys>,
    pub hs_keys: Vec<SessionKeys>,
    pub goal_hops: u8,
    pub circuit_type: CircuitType,
    pub exit_flags: HashSet<PeerFlag>,
    pub relay_early_count: u8,
    pub bytes_up: u32,
    pub bytes_down: u32,
    pub last_activity: u64,
    pub socket: Option<Arc<UdpSocket>>,
}

impl Circuit {
    pub fn new(circuit_id: u32) -> Self {
        Circuit {
            circuit_id,
            peer: SocketAddr::from((Ipv4Addr::from(0), 0)),
            keys: Vec::new(),
            hs_keys: Vec::new(),
            goal_hops: 1,
            circuit_type: CircuitType::Data,
            exit_flags: HashSet::new(),
            relay_early_count: 0,
            bytes_up: 0,
            bytes_down: 0,
            last_activity: 0,
            socket: None,
        }
    }

    pub fn data_ready(&self) -> bool {
        self.circuit_type == CircuitType::Data && self.keys.len() == self.goal_hops as usize
    }

    pub fn encrypt_outgoing_cell(
        &mut self,
        mut packet: Vec<u8>,
        max_relay_early: u8,
    ) -> Result<Vec<u8>, String> {
        let relay_early = self.relay_early_count < max_relay_early;
        packet[28] = (packet[29] == 4 || relay_early) as u8;
        if packet[28] != 0 {
            self.relay_early_count += 1;
        }

        if !self.hs_keys.is_empty() {
            let direction = match self.circuit_type {
                CircuitType::RPSeeder => Direction::Forward,
                _ => Direction::Backward,
            };
            packet = encrypt_cell(&packet, direction, &mut self.hs_keys)?;
        }

        let encrypted_cell = encrypt_cell(&packet, Direction::Forward, &mut self.keys)?;
        self.bytes_up += encrypted_cell.len() as u32;
        Ok(encrypted_cell)
    }

    pub fn decrypt_incoming_cell(
        &mut self,
        packet: &[u8],
        max_relay_early: u8,
    ) -> Result<Vec<u8>, String> {
        let mut decrypted_cell = decrypt_cell(packet, Direction::Backward, &self.keys)?;

        if !self.hs_keys.is_empty() {
            let direction = match self.circuit_type {
                CircuitType::RPDownloader => Direction::Forward,
                _ => Direction::Backward,
            };
            decrypted_cell = decrypt_cell(&decrypted_cell, direction, &mut self.hs_keys)?;
        }

        self.bytes_down += packet.len() as u32;
        self.last_activity = util::get_time();
        check_cell_flags(&decrypted_cell, max_relay_early)?;
        Ok(decrypted_cell)
    }

    pub fn process_incoming_cell(&mut self, decrypted_cell: Vec<u8>) -> Result<Vec<u8>, String> {
        let mut cursor = std::io::Cursor::new(unwrap_cell(&decrypted_cell));
        let mut reader = deku::reader::Reader::new(&mut cursor);
        let data_payload = match payload::DataPayload::from_reader_with_ctx(&mut reader, ()) {
            Ok(p) => p,
            Err(e) => return Err(format!("error decoding data payload: {}", e)),
        };

        let mut origin = data_payload.org_address;
        if self.circuit_type == CircuitType::RPDownloader || self.circuit_type == CircuitType::RPSeeder {
            let ip = circuit_id_to_ip(self.circuit_id);
            origin = Address::V4(SocketAddrV4::new(ip, 1024));
        }

        let socks5_payload = payload::Socks5Payload {
            rsv: 0,
            frag: 0,
            dst: origin,
            data: data_payload.data,
        };

        debug!("Sending packet from circuit {} to SOCKS5 server", self.circuit_id);
        Ok(socks5_payload.to_bytes().unwrap())
    }
}
