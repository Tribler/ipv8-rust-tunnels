use std::net::Ipv4Addr;

use crate::crypto::{decrypt_str, encrypt_str, Direction, SessionKeys};
use crate::payload::{self, Address};
use crate::util::Result;

pub fn encrypt_cell(
    cell: &[u8],
    direction: Direction,
    keys_list: &mut Vec<SessionKeys>,
) -> Result<Vec<u8>> {
    // No encryption needed, cell is plaintext
    if cell[27] != 0 {
        return Ok(cell.to_vec());
    }
    let mut message = (&cell[29..]).to_vec();
    for keys in keys_list.iter_mut().rev() {
        message = match encrypt_str(message, keys, direction) {
            Ok(result) => result,
            Err(error) => return Err(format!("Got error while encrypting cell: {}", error)),
        }
    }
    let mut result = (&cell[..29]).to_vec();
    result.append(&mut message);
    Ok(result)
}

pub fn decrypt_cell(cell: &[u8], direction: Direction, keys_list: &Vec<SessionKeys>) -> Result<Vec<u8>> {
    // No decryption needed, cell is plaintext
    if cell[27] != 0 {
        return Ok(cell.to_vec());
    }
    let mut message = (&cell[29..]).to_vec();
    for keys in keys_list {
        message = match decrypt_str(message, keys, direction) {
            Ok(result) => result,
            Err(error) => return Err(format!("Got error while decrypting cell: {}", error)),
        }
    }
    let mut result = (&cell[..29]).to_vec();
    result.append(&mut message);
    Ok(result)
}

pub fn as_data_cell(
    prefix: &Vec<u8>,
    circuit_id: u32,
    destination: &Address,
    origin: &Address,
    packet: &Vec<u8>,
) -> Vec<u8> {
    let payload = payload::DataPayload {
        header: payload::Header {
            prefix: prefix.to_vec(),
            msg_id: 1,
            circuit_id: circuit_id,
        },
        dest_address: destination.clone(),
        org_address: origin.clone(),
        data: payload::Raw {
            data: packet.to_vec(),
        },
    };
    let data_pkt: Vec<u8> = payload.try_into().unwrap();
    wrap_cell(&data_pkt)
}

pub fn wrap_cell(packet: &Vec<u8>) -> Vec<u8> {
    let prefix = &packet[..22];
    let msg_id = &packet[22..23];
    let circuit_id = &packet[23..27];
    #[rustfmt::skip]
    let plaintext: &[u8] = if crate::payload::NO_CRYPTO_PACKETS.contains(&packet[22]) { &[1] } else { &[0] };
    let msg = &packet[27..];
    [prefix, &[0], circuit_id, plaintext, &[0], msg_id, msg].concat()
}

pub fn unwrap_cell(cell: &Vec<u8>) -> Vec<u8> {
    let prefix = &cell[..22];
    let circuit_id = &cell[23..27];
    let msg_id = &cell[29..30];
    let msg = &cell[30..];
    [prefix, msg_id, circuit_id, msg].concat()
}

pub fn swap_circuit_id(cell: &Vec<u8>, circuit_id: u32) -> Vec<u8> {
    [&cell[..23], &u32::to_be_bytes(circuit_id).to_vec(), &cell[27..]].concat()
}

pub fn is_cell(prefix: &Vec<u8>, packet: &[u8]) -> bool {
    packet.len() > 29 && has_prefix(prefix, packet) && packet[22] == 0
}

pub fn has_prefix(prefix: &[u8], packet: &[u8]) -> bool {
    for i in 0..prefix.len() {
        if packet[i] != prefix[i] {
            return false;
        }
    }
    true
}

pub fn has_prefixes(prefixes: &Vec<Vec<u8>>, packet: &[u8]) -> bool {
    for prefix in prefixes.iter() {
        if has_prefix(prefix, packet) {
            return true;
        }
    }
    false
}

pub fn check_cell_flags(cell: &[u8], max_relay_early: u8) -> Result<()> {
    if (cell[28] == 0 && cell[29] == 4) || max_relay_early <= 0 {
        return Err("Missing or unexpected relay_early flag".to_owned());
    }
    if cell[27] != 0 && !crate::payload::NO_CRYPTO_PACKETS.contains(&cell[29]) {
        return Err("Only create/created can have plaintext flag set".to_owned());
    }
    Ok(())
}

pub fn could_be_utp(packet: &[u8]) -> bool {
    packet.len() >= 20 && (packet[0] >> 4) <= 4 && (packet[0] & 15) == 1 && packet[1] <= 3
}

pub fn could_be_udp_tracker(packet: &[u8]) -> bool {
    (packet.len() >= 8 && u32::from_be_bytes(packet[..4].try_into().unwrap()) <= 3)
        || (packet.len() >= 12 && u32::from_be_bytes(packet[8..12].try_into().unwrap()) <= 3)
}

pub fn could_be_dht(packet: &[u8]) -> bool {
    packet.len() > 1 && packet[0] == b'd' && packet[packet.len() - 1] == b'e'
}

pub fn could_be_bt(packet: &[u8]) -> bool {
    could_be_utp(packet) || could_be_udp_tracker(packet) || could_be_dht(packet)
}

pub fn could_be_ipv8(packet: &[u8]) -> bool {
    packet.len() >= 23 && packet[0] == 0 && (packet[1] == 1 || packet[1] == 2)
}

pub fn ip_to_circuit_id(ip: &Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets().try_into().unwrap())
}

pub fn circuit_id_to_ip(circuit_id: u32) -> Ipv4Addr {
    let buf = u32::to_be_bytes(circuit_id);
    Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])
}
