use std::{
    fmt::Display,
    io::Seek,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
};

use deku::{writer::Writer, DekuError, DekuRead, DekuReader, DekuWrite, DekuWriter};

pub const NO_CRYPTO_PACKETS: [u8; 4] = [2, 3, 31, 33];

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct DataPayload {
    pub header: Header,
    pub dest_address: Address,
    pub org_address: Address,
    pub data: Raw,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct TestRequestPayload {
    pub header: Header,
    pub identifier: u32,
    pub response_size: u16,
    pub request: Raw,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct TestResponsePayload {
    pub header: Header,
    pub identifier: u32,
    pub response: Raw,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct HTTPRequestPayload {
    pub header: Header,
    pub identifier: u32,
    pub target: Address,
    pub request: VarLenH,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct HTTPResponsePayload {
    pub header: Header,
    pub identifier: u32,
    pub part: u16,
    pub total: u16,
    pub response: VarLenH,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub struct Header {
    #[deku(count = "22")]
    pub prefix: Vec<u8>,
    pub msg_id: u8,
    pub circuit_id: u32,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
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
            return Err(DekuError::Parse(std::borrow::Cow::from(format!(
                "failed getting stream position"
            ))));
        };
        let Ok(end_pos) = reader.seek(deku::no_std_io::SeekFrom::End(0)) else {
            return Err(DekuError::Parse(std::borrow::Cow::from(format!(
                "failed getting stream length"
            ))));
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
            reader = "Address::read_v4(deku::reader, endian)",
            writer = "Address::write(deku::writer, &self)"
        )]
        SocketAddrV4,
    ),
    #[deku(id = 3)]
    V6(
        #[deku(
            reader = "Address::read_v6(deku::reader, endian)",
            writer = "Address::write(deku::writer, &self)"
        )]
        SocketAddrV6,
    ),
    #[deku(id = 2)]
    DomainAddress(
        #[deku(
            reader = "Address::read_domain(deku::reader, endian)",
            writer = "Address::write(deku::writer, &self)"
        )]
        (Vec<u8>, u16),
    ),
}

impl Address {
    fn read_v4<R: std::io::Read + std::io::Seek>(
        reader: &mut deku::reader::Reader<R>,
        endian: deku::ctx::Endian,
    ) -> Result<SocketAddrV4, DekuError> {
        let ip = Ipv4Addr::from_reader_with_ctx(reader, endian)?;
        let port = u16::from_reader_with_ctx(reader, endian)?;
        Ok(SocketAddrV4::new(ip, port))
    }

    fn read_v6<R: std::io::Read + std::io::Seek>(
        reader: &mut deku::reader::Reader<R>,
        endian: deku::ctx::Endian,
    ) -> Result<SocketAddrV6, DekuError> {
        let ip = Ipv6Addr::from_reader_with_ctx(reader, endian)?;
        let port = u16::from_reader_with_ctx(reader, endian)?;
        Ok(SocketAddrV6::new(ip, port, 0, 0))
    }

    fn read_domain<R: std::io::Read + std::io::Seek>(
        reader: &mut deku::reader::Reader<R>,
        endian: deku::ctx::Endian,
    ) -> Result<(Vec<u8>, u16), DekuError> {
        let host = VarLenH::from_reader_with_ctx(reader, endian)?.data;
        let port = u16::from_reader_with_ctx(reader, endian)?;
        Ok((host.to_vec(), port))
    }

    fn write<W: std::io::Write + std::io::Seek>(
        writer: &mut Writer<W>,
        address: &Address,
    ) -> Result<(), DekuError> {
        let endian = deku::ctx::Endian::Big;
        match address {
            Address::V4(addr) => {
                addr.ip().octets().to_writer(writer, endian)?;
                addr.port().to_writer(writer, endian)
            }
            Address::DomainAddress((addr, port)) => {
                VarLenH {
                    data_len: addr.len() as u16,
                    data: addr.to_vec(),
                }
                .to_writer(writer, endian)?;
                port.to_writer(writer, endian)
            }
            Address::V6(addr) => {
                addr.ip().octets().to_writer(writer, endian)?;
                addr.port().to_writer(writer, endian)
            }
        }
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::V4(addr) => write!(f, "{addr}"),
            Address::V6(addr) => write!(f, "{addr}"),
            Address::DomainAddress((host, port)) => {
                write!(f, "{hostname}:{port}", hostname = String::from_utf8_lossy(host),)
            }
        }
    }
}

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
                Ok(Address::DomainAddress((host.to_vec(), port)))
            }
            t => Err(DekuError::Parse(std::borrow::Cow::from(format!("unknown address type: {}", t)))),
        }
    }

    fn write_addr<W: std::io::Write + std::io::Seek>(
        writer: &mut Writer<W>,
        address: &Address,
    ) -> Result<(), DekuError> {
        let endian = deku::ctx::Endian::Big;
        let atyp: u8 = match address {
            Address::V4(_) => 1,
            Address::V6(_) => 4,
            Address::DomainAddress((host, port)) => {
                u8::to_writer(&3, writer, endian)?;
                VarLenB {
                    data_len: host.len() as u8,
                    data: host.to_vec(),
                }
                .to_writer(writer, endian)?;
                return port.to_writer(writer, endian);
            }
        };
        atyp.to_writer(writer, endian)?;
        Address::write(writer, address)
    }
}
