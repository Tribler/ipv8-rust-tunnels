use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use socks5_proto::Address;

use crate::crypto::{decrypt_str, encrypt_str, Direction, SessionKeys};
use crate::util::Result;

pub const NO_CRYPTO_PACKETS: [u8; 4] = [2, 3, 31, 33];

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
    let circuit_id = u32::to_be_bytes(circuit_id).to_vec();
    let dest_address = encode_address(destination);
    let org_address = encode_address(origin);
    let data_pkt = [
        prefix.to_vec(),
        vec![1],
        circuit_id,
        dest_address,
        org_address,
        packet.to_vec(),
    ]
    .concat();
    wrap_cell(&data_pkt)
}

pub fn wrap_cell(packet: &Vec<u8>) -> Vec<u8> {
    let prefix = &packet[..22];
    let msg_id = &packet[22..23];
    let circuit_id = &packet[23..27];
    #[rustfmt::skip]
    let plaintext: &[u8] = if NO_CRYPTO_PACKETS.contains(&packet[22]) { &[1] } else { &[0] };
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

pub fn decode_address(packet: &[u8], offset: usize) -> Result<(Address, usize)> {
    let buf = &packet[offset..];
    match buf[0] {
        1 => {
            let addr = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((Address::SocketAddress(SocketAddr::from((addr, port))), offset + 7))
        }
        2 => {
            let len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
            let port = u16::from_be_bytes([buf[len + 3], buf[len + 4]]);
            Ok((Address::DomainAddress(buf[3..len + 3].to_vec(), port), offset + 5 + len))
        }
        3 => {
            let addr = Ipv6Addr::new(
                u16::from_be_bytes([buf[1], buf[2]]),
                u16::from_be_bytes([buf[3], buf[4]]),
                u16::from_be_bytes([buf[5], buf[6]]),
                u16::from_be_bytes([buf[7], buf[8]]),
                u16::from_be_bytes([buf[9], buf[10]]),
                u16::from_be_bytes([buf[11], buf[12]]),
                u16::from_be_bytes([buf[13], buf[14]]),
                u16::from_be_bytes([buf[15], buf[16]]),
            );
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((Address::SocketAddress(SocketAddr::from((addr, port))), offset + 19))
        }
        _ => Err(format!("Invalid address type {}", buf[0])),
    }
}

pub fn encode_address(address: &Address) -> Vec<u8> {
    match address {
        Address::SocketAddress(SocketAddr::V4(addr)) => {
            let mut result: Vec<u8> = vec![1];
            result.extend_from_slice(&addr.ip().octets());
            result.extend_from_slice(&u16::to_be_bytes(addr.port()));
            result
        }
        Address::DomainAddress(addr, port) => {
            let mut result: Vec<u8> = vec![2];
            result.extend_from_slice(&u16::to_be_bytes(addr.len() as u16));
            result.extend_from_slice(&addr);
            result.extend_from_slice(&u16::to_be_bytes(*port));
            result
        }
        Address::SocketAddress(SocketAddr::V6(addr)) => {
            let mut result: Vec<u8> = vec![3];
            result.extend_from_slice(&addr.ip().octets());
            result.extend_from_slice(&u16::to_be_bytes(addr.port()));
            result
        }
    }
}

pub fn check_cell_flags(cell: &[u8], max_relay_early: u8) -> Result<()> {
    if (cell[28] == 0 && cell[29] == 4) || max_relay_early <= 0 {
        return Err("Missing or unexpected relay_early flag".to_owned());
    }
    if cell[27] != 0 && !NO_CRYPTO_PACKETS.contains(&cell[29]) {
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
