use std::fmt::{self, Display};
use std::io::{Seek, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use deku::reader::Reader;
use deku::writer::Writer;
use deku::{DekuContainerWrite, DekuError, DekuRead, DekuReader, DekuWrite, DekuWriter};

use crate::crypto::cipher::{Direction, SessionKeys};
use crate::crypto::keys::PublicKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolDomain {
    Core,
    HiddenServices,
    DataStream,
}

// =========================================================================
// Message definitions
// =========================================================================

pub const NO_CRYPTO_PACKETS: [u8; 2] = [CellId::Create as u8, CellId::Created as u8];
pub const ALLOWED_CELLS_FW: [u8; 13] = [
    CellId::Data as u8,
    CellId::Create as u8,
    CellId::Extend as u8,
    CellId::Ping as u8,
    CellId::Destroy as u8,
    CellId::EstablishIntro as u8,
    CellId::EstablishRendezvous as u8,
    CellId::CreateE2E as u8,
    CellId::CreatedE2E as u8,
    CellId::LinkE2E as u8,
    CellId::LinkedE2E as u8,
    CellId::TestRequest as u8,
    CellId::HttpRequest as u8,
];

pub const ALLOWED_CELLS_BW: [u8; 13] = [
    CellId::Data as u8,
    CellId::Created as u8,
    CellId::Extended as u8,
    CellId::Pong as u8,
    CellId::Destroy as u8,
    CellId::IntroEstablished as u8,
    CellId::RendezvousEstablished as u8,
    CellId::CreateE2E as u8,
    CellId::CreatedE2E as u8,
    CellId::LinkE2E as u8,
    CellId::LinkedE2E as u8,
    CellId::TestResponse as u8,
    CellId::HttpResponse as u8,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageId {
    Cell = 0,
    Destroy = 8,
    CreateE2E = 13,
    CreatedE2E = 14,
    PeersRequest = 17,
    PeersResponse = 18,
}

impl MessageId {
    pub fn domain(self) -> ProtocolDomain {
        match self {
            MessageId::CreateE2E
            | MessageId::CreatedE2E
            | MessageId::PeersRequest
            | MessageId::PeersResponse => ProtocolDomain::HiddenServices,
            _ => ProtocolDomain::Core,
        }
    }
}

impl TryFrom<u8> for MessageId {
    type Error = String;

    #[inline]
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MessageId::Cell),
            8 => Ok(MessageId::Destroy),
            13 => Ok(MessageId::CreateE2E),
            14 => Ok(MessageId::CreatedE2E),
            17 => Ok(MessageId::PeersRequest),
            18 => Ok(MessageId::PeersResponse),
            _ => Err(format!("Unknown message ID: {}", value)),
        }
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CellId {
    Data = 1,
    Create = 2,
    Created = 3,
    Extend = 4,
    Extended = 5,
    Ping = 6,
    Pong = 7,
    Destroy = 8,
    EstablishIntro = 9,
    IntroEstablished = 10,
    EstablishRendezvous = 11,
    RendezvousEstablished = 12,
    CreateE2E = 13,
    CreatedE2E = 14,
    LinkE2E = 15,
    LinkedE2E = 16,
    TestRequest = 21,
    TestResponse = 22,
    HttpRequest = 28,
    HttpResponse = 29,
}

impl CellId {
    pub fn domain(self) -> ProtocolDomain {
        match self {
            CellId::Data => ProtocolDomain::DataStream,

            CellId::EstablishIntro
            | CellId::IntroEstablished
            | CellId::EstablishRendezvous
            | CellId::RendezvousEstablished
            | CellId::CreatedE2E
            | CellId::LinkE2E
            | CellId::LinkedE2E
            | CellId::CreateE2E => ProtocolDomain::HiddenServices,

            _ => ProtocolDomain::Core,
        }
    }
}

impl TryFrom<u8> for CellId {
    type Error = String;

    #[inline]
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(CellId::Data),
            2 => Ok(CellId::Create),
            3 => Ok(CellId::Created),
            4 => Ok(CellId::Extend),
            5 => Ok(CellId::Extended),
            6 => Ok(CellId::Ping),
            7 => Ok(CellId::Pong),
            8 => Ok(CellId::Destroy),
            9 => Ok(CellId::EstablishIntro),
            10 => Ok(CellId::IntroEstablished),
            11 => Ok(CellId::EstablishRendezvous),
            12 => Ok(CellId::RendezvousEstablished),
            13 => Ok(CellId::CreateE2E),
            14 => Ok(CellId::CreatedE2E),
            15 => Ok(CellId::LinkE2E),
            16 => Ok(CellId::LinkedE2E),
            21 => Ok(CellId::TestRequest),
            22 => Ok(CellId::TestResponse),
            28 => Ok(CellId::HttpRequest),
            29 => Ok(CellId::HttpResponse),
            _ => Err(format!("Unknown cell ID: {}", value)),
        }
    }
}

impl fmt::Display for CellId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DestroyReason {
    Unknown = 1,
    Shutdown = 2,
    Unneeded = 4,
}

// =========================================================================
// Basic onion routing
// =========================================================================

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x01")]
pub struct DataPayload {
    pub circuit_id: u32,
    pub dest_address: Address,
    pub org_address: Address,
    pub data: Raw,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x02")]
pub struct CreatePayload {
    pub circuit_id: u32,
    pub identifier: u16,
    pub node_public_key: VarLenH,
    pub key: VarLenH,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x03")]
pub struct CreatedPayload {
    pub circuit_id: u32,
    pub identifier: u16,
    pub key: VarLenH,
    pub auth: [u8; 32],
    pub candidates_enc: Raw,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x04")]
pub struct ExtendPayload {
    pub circuit_id: u32,
    pub identifier: u16,
    pub node_public_key: VarLenH,
    pub key: VarLenH,
    pub node_addr: Address,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x05")]
pub struct ExtendedPayload {
    pub circuit_id: u32,
    pub identifier: u16,
    pub key: VarLenH,
    pub auth: [u8; 32],
    pub candidates_enc: Raw,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x06")]
pub struct PingPayload {
    pub circuit_id: u32,
    pub identifier: u16,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x07")]
pub struct PongPayload {
    pub circuit_id: u32,
    pub identifier: u16,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x08")]
pub struct DestroyPayload {
    pub circuit_id: u32,
    pub reason: u16,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x15")]
pub struct TestRequestPayload {
    pub circuit_id: u32,
    pub identifier: u32,
    pub response_size: u16,
    pub request: Raw,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x16")]
pub struct TestResponsePayload {
    pub circuit_id: u32,
    pub identifier: u32,
    pub response: Raw,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x1c")]
pub struct HTTPRequestPayload {
    pub circuit_id: u32,
    pub identifier: u32,
    pub target: Address,
    pub request: VarLenH,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x1d")]
pub struct HTTPResponsePayload {
    pub circuit_id: u32,
    pub identifier: u32,
    pub part: u16,
    pub total: u16,
    pub response: VarLenH,
}

#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
pub struct CandidateKey {
    #[deku(endian = "big")]
    pub length: u16,
    #[deku(count = "length")]
    pub public_key_bin: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
pub struct CandidatePayload {
    pub count: u8,
    #[deku(count = "count")]
    pub keys: Vec<CandidateKey>,
}

impl CandidatePayload {
    pub fn from_candidates(peers_keys: Vec<Vec<u8>>) -> Result<Vec<u8>, String> {
        let payload = Self {
            count: peers_keys.len() as u8,
            keys: peers_keys
                .into_iter()
                .map(|key| CandidateKey { length: key.len() as u16, public_key_bin: key })
                .collect(),
        };

        payload.to_bytes().map_err(|e| format!("failed to decode candidate list: {e}"))
    }
}

// =========================================================================
// Hidden services
// =========================================================================

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x09")]
pub struct EstablishIntroPayload {
    pub circuit_id: u32,
    pub identifier: u16,
    pub info_hash: [u8; 20],
    pub public_key: VarLenH,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x0a")]
pub struct IntroEstablishedPayload {
    pub circuit_id: u32,
    pub identifier: u16,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x0b")]
pub struct EstablishRendezvousPayload {
    pub circuit_id: u32,
    pub identifier: u16,
    pub cookie: [u8; 20],
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x0c")]
pub struct RendezvousEstablishedPayload {
    pub circuit_id: u32,
    pub identifier: u16,
    pub rendezvous_point_addr: Address,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x0d")]
pub struct CreateE2EPayload {
    pub circuit_id: u32,
    pub identifier: u16,
    pub info_hash: [u8; 20],
    pub node_public_key: VarLenH,
    pub key: VarLenH,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x0e")]
pub struct CreatedE2EPayload {
    pub circuit_id: u32,
    pub identifier: u16,
    pub key: VarLenH,
    pub auth: [u8; 32],
    pub rp_info_enc: Raw,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x0f")]
pub struct LinkE2EPayload {
    pub circuit_id: u32,
    pub identifier: u16,
    pub cookie: [u8; 20],
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
#[deku(magic = b"\x10")]
pub struct LinkedE2EPayload {
    pub circuit_id: u32,
    pub identifier: u16,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct RendezvousInfo {
    pub address: Address,
    pub key: VarLenH,
    pub cookie: [u8; 20],
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub struct Header {
    pub prefix: [u8; 22],
    pub msg_id: u8,
    pub circuit_id: u32,
}

// =========================================================================
// Helpers
// =========================================================================

#[derive(Debug, Clone, Ord, PartialOrd, DekuRead, DekuWrite, PartialEq, Eq, Hash)]
#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub struct VarLenH {
    #[deku(update = "self.data.len()")]
    pub data_len: u16,
    #[deku(count = "data_len")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub struct VarLenB {
    #[deku(update = "self.data.len()")]
    pub data_len: u8,
    #[deku(count = "data_len")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub struct Raw {
    #[deku(reader = "Raw::read(deku::reader)", writer = "Raw::write(deku::writer, &self.data)")]
    pub data: Vec<u8>,
}

impl Raw {
    fn read<R: std::io::Read + std::io::Seek>(
        reader: &mut deku::reader::Reader<R>,
    ) -> Result<Vec<u8>, DekuError> {
        let Ok(begin_pos) = reader.stream_position() else {
            return Err(DekuError::Parse(std::borrow::Cow::from(format!("failed getting stream position"))));
        };
        let Ok(end_pos) = reader.seek(deku::no_std_io::SeekFrom::End(0)) else {
            return Err(DekuError::Parse(std::borrow::Cow::from(format!("failed getting stream length"))));
        };
        let len = (end_pos - begin_pos) as usize;
        let mut buf = vec![0; len];
        let _ = reader.seek(deku::no_std_io::SeekFrom::Start(begin_pos));
        let _ = reader.read_bytes(len as usize, &mut buf, deku::ctx::Order::Msb0);
        Ok(buf)
    }

    fn write<W: std::io::Write + std::io::Seek>(
        writer: &mut Writer<W>,
        data: &Vec<u8>,
    ) -> Result<(), DekuError> {
        data.to_writer(writer, ())
    }
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub enum Address {
    #[deku(id = 1)]
    V4(
        #[deku(
            reader = "Self::read_v4(deku::reader, endian)",
            writer = "Self::write_v4(deku::writer, endian, field_0)"
        )]
        SocketAddrV4,
    ),
    #[deku(id = 3)]
    V6(
        #[deku(
            reader = "Self::read_v6(deku::reader, endian)",
            writer = "Self::write_v6(deku::writer, endian, field_0)"
        )]
        SocketAddrV6,
    ),
    #[deku(id = 2)]
    DomainAddress(VarLenH, u16),
}

impl Address {
    fn read_v4<R: deku::no_std_io::Read + deku::no_std_io::Seek>(
        reader: &mut deku::reader::Reader<R>,
        endian: deku::ctx::Endian,
    ) -> Result<SocketAddrV4, DekuError> {
        let octets = <[u8; 4]>::from_reader_with_ctx(reader, endian)?;
        let port = u16::from_reader_with_ctx(reader, endian)?;
        Ok(SocketAddrV4::new(Ipv4Addr::from(octets), port))
    }

    fn write_v4<W: deku::no_std_io::Write + deku::no_std_io::Seek>(
        writer: &mut deku::writer::Writer<W>,
        endian: deku::ctx::Endian,
        field: &SocketAddrV4,
    ) -> Result<(), DekuError> {
        field.ip().octets().to_writer(writer, endian)?;
        field.port().to_writer(writer, endian)
    }

    fn read_v6<R: deku::no_std_io::Read + deku::no_std_io::Seek>(
        reader: &mut deku::reader::Reader<R>,
        endian: deku::ctx::Endian,
    ) -> Result<SocketAddrV6, DekuError> {
        let octets = <[u8; 16]>::from_reader_with_ctx(reader, endian)?;
        let port = u16::from_reader_with_ctx(reader, endian)?;
        Ok(SocketAddrV6::new(Ipv6Addr::from(octets), port, 0, 0))
    }

    fn write_v6<W: deku::no_std_io::Write + deku::no_std_io::Seek>(
        writer: &mut deku::writer::Writer<W>,
        endian: deku::ctx::Endian,
        field: &SocketAddrV6,
    ) -> Result<(), DekuError> {
        field.ip().octets().to_writer(writer, endian)?;
        field.port().to_writer(writer, endian)
    }

    pub fn write<W: deku::no_std_io::Write + deku::no_std_io::Seek>(
        writer: &mut deku::writer::Writer<W>,
        address: &Address,
    ) -> Result<(), DekuError> {
        address.to_writer(writer, deku::ctx::Endian::Big)
    }

    pub fn hostname(&self) -> Option<String> {
        match self {
            Address::DomainAddress(var_len, _) => Some(String::from_utf8_lossy(&var_len.data).into_owned()),
            _ => None,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Address::V4(addr) => addr.port(),
            Address::V6(addr) => addr.port(),
            Address::DomainAddress(_, port) => *port,
        }
    }

    pub fn is_unspecified(&self) -> bool {
        match self {
            Address::V4(addr) => addr.ip().is_unspecified() && addr.port() == 0,
            Address::V6(addr) => addr.ip().is_unspecified() && addr.port() == 0,
            Address::DomainAddress(var_len, port) => {
                let host = &var_len.data;
                *port == 0
                    && (var_len.data_len == 0 || host.is_empty() || host == b"0.0.0.0" || host == b"::")
            }
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(socket_addr: SocketAddr) -> Self {
        match socket_addr {
            SocketAddr::V4(addr) => Address::V4(addr),
            SocketAddr::V6(addr) => Address::V6(addr),
        }
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::V4(addr) => write!(f, "{addr}"),
            Address::V6(addr) => write!(f, "{addr}"),
            Address::DomainAddress(var_len, port) => {
                write!(f, "{}:{}", String::from_utf8_lossy(&var_len.data), port)
            }
        }
    }
}

// =========================================================================
// SOCKS5
// =========================================================================

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct Socks5Payload {
    pub rsv: u16,
    pub frag: u8,
    #[deku(
        reader = "Socks5Payload::read_addr(deku::reader)",
        writer = "Socks5Payload::write_addr(deku::writer, &self.dst)"
    )]
    pub dst: Address,
    pub data: Raw,
}

impl Socks5Payload {
    fn read_addr<R: std::io::Read + std::io::Seek>(
        reader: &mut deku::reader::Reader<R>,
    ) -> Result<Address, DekuError> {
        let endian = deku::ctx::Endian::Big;
        match u8::from_reader_with_ctx(reader, endian)? {
            1 => Ok(Address::V4(Address::read_v4(reader, endian)?)),
            4 => Ok(Address::V6(Address::read_v6(reader, endian)?)),
            3 => {
                let host = VarLenB::from_reader_with_ctx(reader, deku::ctx::Endian::Big)?.data;
                let port = u16::from_reader_with_ctx(reader, endian)?;

                Ok(Address::DomainAddress(VarLenH { data_len: host.len() as u16, data: host.to_vec() }, port))
            }
            t => Err(DekuError::Parse(std::borrow::Cow::from(format!("unknown address type: {}", t)))),
        }
    }

    fn write_addr<W: deku::no_std_io::Write + deku::no_std_io::Seek>(
        writer: &mut deku::writer::Writer<W>,
        address: &Address,
    ) -> Result<(), DekuError> {
        let endian = deku::ctx::Endian::Big;

        match address {
            Address::V4(inner_v4) => {
                u8::to_writer(&1, writer, endian)?;
                Address::write_v4(writer, endian, inner_v4)
            }
            Address::V6(inner_v6) => {
                u8::to_writer(&4, writer, endian)?;
                Address::write_v6(writer, endian, inner_v6)
            }
            Address::DomainAddress(var_len, port) => {
                u8::to_writer(&3, writer, endian)?;
                u8::to_writer(&(var_len.data.len() as u8), writer, endian)?;
                var_len.data.to_writer(writer, endian)?;
                port.to_writer(writer, endian)
            }
        }
    }
}

pub fn unpack_cell_payload<T: for<'a> DekuReader<'a, ()>>(cell: &mut Vec<u8>) -> Result<T, String> {
    // Warning: Modifies the underlying vector in place before parsing.
    let mut cursor = std::io::Cursor::new(&*cell);
    let mut reader = Reader::new(&mut cursor);

    T::from_reader_with_ctx(&mut reader, ()).map_err(|e| {
        let full_name = std::any::type_name::<T>();
        let short_name = full_name.split("::").last().unwrap_or(full_name);
        format!("error decoding cell payload {}: {}", short_name, e)
    })
}

pub fn unpack_signed_payload<T>(packet: &[u8]) -> Result<(PublicKey, T), String>
where
    T: for<'a> deku::DekuContainerRead<'a>,
{
    if packet.len() < 25 {
        return Err("Packet too short for IPv8 header".to_owned());
    }

    let key_len = u16::from_be_bytes([packet[23], packet[24]]) as usize;
    let key_end = 25 + key_len;
    let key_slice = packet.get(25..key_end).ok_or_else(|| "cannot get public key".to_owned())?;

    let peer_pk = PublicKey::from_bytes(key_slice).map_err(|e| format!("invalid public key: {}", e))?;

    let sig_len = peer_pk.get_signature_length();
    let payload_end = packet
        .len()
        .checked_sub(sig_len)
        .filter(|&end| key_end <= end)
        .ok_or_else(|| "invalid signature bounds".to_owned())?;
    if !peer_pk.verify(&packet[payload_end..], &packet[..payload_end]) {
        return Err("invalid signature".to_owned());
    }

    let (_, inner_payload) = T::from_bytes((&packet[key_end..payload_end], 0))
        .map_err(|e| format!("deserialization failed: {:?}", e))?;

    Ok((peer_pk, inner_payload))
}

#[inline(always)]
pub fn unpack_data(buffer: &mut Vec<u8>) -> Option<(Address, Address, &mut Vec<u8>)> {
    if buffer.len() < 14 || buffer[0] != CellId::Data as u8 {
        return None;
    }

    let mut cursor = std::io::Cursor::new(&*buffer);
    cursor.set_position(5);

    let mut reader = deku::reader::Reader::new(&mut cursor);
    let dest_addr = Address::from_reader_with_ctx(&mut reader, deku::ctx::Endian::Big).ok()?;
    let origin_addr = Address::from_reader_with_ctx(&mut reader, deku::ctx::Endian::Big).ok()?;
    let payload_offset = cursor.position() as usize;
    let total_len = buffer.len();

    if total_len < payload_offset {
        return None;
    }

    // We're doing the actual unwrapping in-place.
    let payload_len = total_len - payload_offset;
    if payload_len > 0 {
        buffer.copy_within(payload_offset..total_len, 0);
        buffer.truncate(payload_len);
    } else {
        buffer.clear();
    }

    Some((dest_addr, origin_addr, buffer))
}

pub fn is_cell(prefix: &Vec<u8>, packet: &[u8]) -> bool {
    packet.len() > 29 && has_prefix(prefix, packet) && packet[22] == 0
}

pub fn has_prefix(prefix: &[u8], packet: &[u8]) -> bool {
    packet.starts_with(prefix)
}

pub fn has_prefixes(prefixes: &Vec<Vec<u8>>, packet: &[u8]) -> bool {
    for prefix in prefixes.iter() {
        if has_prefix(prefix, packet) {
            return true;
        }
    }
    false
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

pub struct CellPayload<'a> {
    pub buffer: &'a mut Vec<u8>,
}

impl<'a> CellPayload<'a> {
    #[inline(always)]
    pub fn from_packet(buffer: &'a mut Vec<u8>) -> Result<Self, String> {
        // Cell format:
        // [0] msg_id, [1..5] circuit_id, [5] plaintext, [6] relay_early, [7] cell_id, [8..] payload
        if buffer.len() < 8 {
            return Err("Cell too small".to_owned());
        }
        Ok(Self { buffer })
    }

    #[inline(always)]
    pub fn from_payload(buffer: &'a mut Vec<u8>, plaintext: bool, relay_early: bool) -> Result<Self, String> {
        // Payload format:
        // [0] cell_id, [1..5] circuit_id, [5..] payload
        let msg_len = buffer.len();
        if msg_len < 5 {
            return Err("Cell payload too small".to_owned());
        }

        buffer.resize(msg_len + 3, 0);
        // Move the payload 3 bytes back
        buffer.copy_within(5..msg_len, 8);
        // Move the cell_id
        buffer[7] = buffer[0];
        // Set msg_id (cell=0)
        buffer[0] = MessageId::Cell as u8;
        // Set the flags
        buffer[5] = plaintext as u8;
        buffer[6] = relay_early as u8;

        Ok(Self { buffer })
    }

    #[inline(always)]
    pub fn from_data(
        circuit_id: u32,
        destination: &Address,
        origin: &Address,
        data: &[u8],
        buffer: &'a mut Vec<u8>,
    ) -> Result<Self, String> {
        buffer.clear();
        let mut cursor = std::io::Cursor::new(&mut *buffer);
        cursor.write_all(&[0u8]).map_err(|e| e.to_string())?; // msg_id = 0 (cell)
        cursor.write_all(&circuit_id.to_be_bytes()).map_err(|e| e.to_string())?;
        cursor.write_all(&[0u8]).map_err(|e| e.to_string())?; // plaintext = false
        cursor.write_all(&[0u8]).map_err(|e| e.to_string())?; // relay_early = false
        cursor.write_all(&[1u8]).map_err(|e| e.to_string())?; // cell_id = 1 (data)

        {
            let mut writer = Writer::new(&mut cursor);
            Address::write(&mut writer, destination)
                .map_err(|e| format!("Failed to serialize destination address: {}", e))?;
            Address::write(&mut writer, origin)
                .map_err(|e| format!("Failed to serialize origin address: {}", e))?;
        }

        cursor.write_all(data).map_err(|e| e.to_string())?;
        drop(cursor);
        Ok(Self { buffer })
    }

    #[inline(always)]
    pub fn circuit_id(&self) -> u32 {
        u32::from_be_bytes(self.buffer[1..5].try_into().unwrap())
    }

    #[inline(always)]
    pub fn is_plaintext(&self) -> bool {
        self.buffer[5] != 0
    }

    #[inline(always)]
    pub fn set_plaintext(&mut self, plaintext: bool) {
        self.buffer[5] = plaintext as u8;
    }

    #[inline(always)]
    pub fn is_relay_early(&self) -> bool {
        self.buffer[6] != 0
    }

    #[inline(always)]
    pub fn set_relay_early(&mut self, relay_early: bool) {
        self.buffer[6] = relay_early as u8;
    }

    #[inline(always)]
    pub fn cell_id(&self) -> u8 {
        self.buffer[7]
    }

    #[inline(always)]
    pub fn payload(&self) -> &[u8] {
        &self.buffer[8..]
    }

    #[inline(always)]
    pub fn encrypt(&mut self, direction: Direction, keys_list: &[SessionKeys]) -> Result<(), String> {
        if self.is_plaintext() {
            return Ok(());
        }

        let mut header = [0u8; 7];
        header.copy_from_slice(&self.buffer[..7]);
        self.buffer.drain(..7);

        for keys in keys_list.iter().rev() {
            keys.encrypt_in_place(self.buffer, direction)?;
        }

        let cypher_len = self.buffer.len();
        self.buffer.resize(cypher_len + 7, 0);
        self.buffer.copy_within(0..cypher_len, 7);
        self.buffer[..7].copy_from_slice(&header);

        Ok(())
    }

    #[inline(always)]
    pub fn decrypt(&mut self, direction: Direction, keys_list: &[SessionKeys]) -> Result<(), String> {
        if self.is_plaintext() {
            return Ok(());
        }

        let mut header = [0u8; 7];
        header.copy_from_slice(&self.buffer[..7]);
        self.buffer.drain(..7);

        for keys in keys_list {
            keys.decrypt_in_place(self.buffer, direction)?;
        }

        let plain_len = self.buffer.len();
        self.buffer.resize(plain_len + 7, 0);
        self.buffer.copy_within(0..plain_len, 7);
        self.buffer[..7].copy_from_slice(&header);

        Ok(())
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    #[inline(always)]
    pub fn swap_circuit_id(&mut self, new_circuit_id: u32) {
        self.buffer[1..5].copy_from_slice(&new_circuit_id.to_be_bytes());
    }

    #[inline(always)]
    pub fn check(&self, relay_early_left: u8, exit_enabled: bool) -> Result<(), String> {
        if self.len() < 8 {
            return Err(format!("Cell too short ({})", self.len()));
        }

        let cell_id = self.cell_id();

        if self.is_relay_early() {
            if relay_early_left == 0 {
                return Err("Maximum number of relay_early cells reached".to_owned());
            }

            if exit_enabled {
                // Exit rules: only Extend (4) or Data (1) are allowed to set relay_early
                if cell_id != 4 && cell_id != 1 {
                    return Err(format!("Unexpected relay_early cell_id ({})", cell_id));
                }
            }
        } else if cell_id == 4 {
            return Err("Extend cell missing mandatory relay_early flag".to_owned());
        }

        if self.is_plaintext() && !NO_CRYPTO_PACKETS.contains(&cell_id) {
            return Err(format!("Plaintext flag set on unapproved cell_id {}", cell_id));
        }

        Ok(())
    }

    #[inline(always)]
    pub fn unwrap(self) -> &'a mut Vec<u8> {
        let msg_id = self.buffer[7];
        let mut circuit_id_bytes = [0u8; 4];
        circuit_id_bytes.copy_from_slice(&self.buffer[1..5]);

        self.buffer.drain(5..7);
        self.buffer.drain(0..1);

        self.buffer[0] = msg_id;
        self.buffer[1..5].copy_from_slice(&circuit_id_bytes[..4]);
        // Because we take 'self' by value, ensuring this struct get destroyed.
        // This way, we can't call it twice.
        self.buffer
    }
}
