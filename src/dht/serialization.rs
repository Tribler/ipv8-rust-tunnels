use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use bencode::{util::ByteString, Bencode, FromBencode, ToBencode};

use crate::dht::storage::Node;

#[inline(always)]
pub fn unwrap_dict(bencode: &Bencode) -> Result<&BTreeMap<ByteString, Bencode>, String> {
    let Bencode::Dict(ref m) = bencode else {
        return Err("Not a dict".into());
    };
    Ok(m)
}

pub trait BencodeMapExt {
    fn get_bytes(&self, key: &str) -> Result<Vec<u8>, String>;
    fn get_num(&self, key: &str) -> Result<i64, String>;
    fn get_array<const N: usize>(&self, key: &str) -> Result<[u8; N], String>;
    fn get_list<T, F>(&self, key: &str, is_optional: bool, map_fn: F) -> Result<Option<Vec<T>>, String>
    where
        F: FnMut(Bencode) -> Result<T, String>;

    fn set_bytes(&mut self, key: &str, value: Vec<u8>);
    fn set_num(&mut self, key: &str, value: i64);
    fn set_list<T, F>(&mut self, key: &str, value: &Option<Vec<T>>, map_fn: F)
    where
        F: FnMut(&T) -> Bencode;
}

impl BencodeMapExt for BTreeMap<ByteString, Bencode> {
    #[inline(always)]
    fn get_bytes(&self, key: &str) -> Result<Vec<u8>, String> {
        self.get(&ByteString::from_str(key))
            .and_then(|b| if let Bencode::ByteString(v) = b { Some(v.clone()) } else { None })
            .ok_or_else(|| format!("Missing or malformed byte field: {}", key))
    }

    #[inline(always)]
    fn get_num(&self, key: &str) -> Result<i64, String> {
        self.get(&ByteString::from_str(key))
            .and_then(|b| if let Bencode::Number(n) = b { Some(*n) } else { None })
            .ok_or_else(|| format!("Missing or malformed numeric field: {}", key))
    }

    #[inline(always)]
    fn get_array<const N: usize>(&self, key: &str) -> Result<[u8; N], String> {
        let bytes = self.get_bytes(key)?;
        bytes.try_into().map_err(|_| format!("Missing or malformed array {} field: {}.", N, key))
    }

    #[inline(always)]
    fn get_list<T, F>(&self, key: &str, is_optional: bool, mut map_fn: F) -> Result<Option<Vec<T>>, String>
    where
        F: FnMut(Bencode) -> Result<T, String>,
    {
        match self.get(&ByteString::from_str(key)) {
            Some(Bencode::List(list)) => {
                let mut items = Vec::with_capacity(list.len());
                for item in list {
                    items.push(map_fn(item.clone())?);
                }
                Ok(Some(items))
            }
            Some(_) => Err(format!("Field '{}' must be a list", key)),
            None => {
                if is_optional {
                    Ok(None)
                } else {
                    Err(format!("Required field '{}' is missing.", key))
                }
            }
        }
    }

    #[inline(always)]
    fn set_bytes(&mut self, key: &str, value: Vec<u8>) {
        self.insert(ByteString::from_str(key), Bencode::ByteString(value));
    }

    #[inline(always)]
    fn set_num(&mut self, key: &str, value: i64) {
        self.insert(ByteString::from_str(key), Bencode::Number(value));
    }

    #[inline(always)]
    fn set_list<T, F>(&mut self, key: &str, value: &Option<Vec<T>>, mut map_fn: F)
    where
        F: FnMut(&T) -> Bencode,
    {
        if let Some(ref list) = value {
            let items = list.iter().map(|item| map_fn(item)).collect();
            self.insert(ByteString::from_str(key), Bencode::List(items));
        }
    }
}

#[derive(Debug, Clone)]
pub struct DhtQuery {
    pub t: Vec<u8>,
    pub y: Vec<u8>,
    pub q: Vec<u8>,
    pub a: Option<BTreeMap<ByteString, Bencode>>,
    pub r: Option<BTreeMap<ByteString, Bencode>>,
}

impl DhtQuery {
    #[inline(always)]
    pub fn transaction_id(&self) -> Result<u16, String> {
        if self.t.len() == 2 {
            Ok(u16::from_be_bytes([self.t[0], self.t[1]]))
        } else {
            Err("Transaction ID must be 2 bytes long.".to_owned())
        }
    }

    #[inline(always)]
    pub fn from_buffer(buf: &[u8]) -> Result<Self, String> {
        let bencode_node =
            bencode::from_buffer(buf).map_err(|e| format!("Failed to decode Bencode stream: {:?}", e))?;
        Self::from_bencode(&bencode_node)
    }
}

impl ToBencode for DhtQuery {
    fn to_bencode(&self) -> Bencode {
        let mut m = BTreeMap::new();
        m.insert(ByteString::from_str("t"), Bencode::ByteString(self.t.clone()));
        m.insert(ByteString::from_str("y"), Bencode::ByteString(self.y.clone()));

        if !self.q.is_empty() {
            m.insert(ByteString::from_str("q"), Bencode::ByteString(self.q.clone()));
        }
        if let Some(ref a_dict) = self.a {
            m.insert(ByteString::from_str("a"), Bencode::Dict(a_dict.clone()));
        }
        if let Some(ref r_dict) = self.r {
            m.insert(ByteString::from_str("r"), Bencode::Dict(r_dict.clone()));
        }

        Bencode::Dict(m)
    }
}

impl FromBencode for DhtQuery {
    type Err = String;

    fn from_bencode(bencode: &Bencode) -> Result<Self, String> {
        let m = unwrap_dict(bencode)?;

        let t = m.get_bytes("t")?;
        let y = m.get_bytes("y")?;
        let a = m.get(&ByteString::from_str("a")).and_then(|b| unwrap_dict(b).ok()).cloned();
        let r = m.get(&ByteString::from_str("r")).and_then(|b| unwrap_dict(b).ok()).cloned();
        let q = m.get_bytes("q").unwrap_or_default();

        Ok(DhtQuery { t, y, q, a, r })
    }
}

#[derive(Debug, Clone)]
pub struct PingPayload {
    pub id: [u8; 20],
}
impl ToBencode for PingPayload {
    fn to_bencode(&self) -> Bencode {
        let mut m = BTreeMap::new();
        m.set_bytes("id", self.id.to_vec());
        Bencode::Dict(m)
    }
}
impl FromBencode for PingPayload {
    type Err = String;
    fn from_bencode(b: &Bencode) -> Result<Self, String> {
        let m = unwrap_dict(b)?;
        Ok(PingPayload { id: m.get_array("id")? })
    }
}

#[derive(Debug, Clone)]
pub struct FindNodeRequest {
    pub id: [u8; 20],
    pub target: [u8; 20],
}
impl ToBencode for FindNodeRequest {
    fn to_bencode(&self) -> Bencode {
        let mut m = BTreeMap::new();
        m.set_bytes("id", self.id.to_vec());
        m.set_bytes("target", self.target.to_vec());
        Bencode::Dict(m)
    }
}
impl FromBencode for FindNodeRequest {
    type Err = String;
    fn from_bencode(b: &Bencode) -> Result<Self, String> {
        let m = unwrap_dict(b)?;
        Ok(FindNodeRequest { id: m.get_array("id")?, target: m.get_array("target")? })
    }
}

#[derive(Debug, Clone)]
pub struct FindNodeResponse {
    pub id: [u8; 20],
    pub nodes: Vec<u8>,
}
impl ToBencode for FindNodeResponse {
    fn to_bencode(&self) -> Bencode {
        let mut m = BTreeMap::new();
        m.set_bytes("id", self.id.to_vec());
        m.set_bytes("nodes", self.nodes.clone());
        Bencode::Dict(m)
    }
}
impl FromBencode for FindNodeResponse {
    type Err = String;
    fn from_bencode(b: &Bencode) -> Result<Self, String> {
        let m = unwrap_dict(b)?;
        Ok(FindNodeResponse { id: m.get_array("id")?, nodes: m.get_bytes("nodes")? })
    }
}

#[derive(Debug, Clone)]
pub struct GetPeersRequest {
    pub id: [u8; 20],
    pub info_hash: [u8; 20],
}
impl ToBencode for GetPeersRequest {
    fn to_bencode(&self) -> Bencode {
        let mut m = BTreeMap::new();
        m.set_bytes("id", self.id.to_vec());
        m.set_bytes("info_hash", self.info_hash.to_vec());
        Bencode::Dict(m)
    }
}
impl FromBencode for GetPeersRequest {
    type Err = String;
    fn from_bencode(b: &Bencode) -> Result<Self, String> {
        let m = unwrap_dict(b)?;
        Ok(GetPeersRequest { id: m.get_array("id")?, info_hash: m.get_array("info_hash")? })
    }
}

#[derive(Debug, Clone)]
pub struct GetPeersResponse {
    pub id: [u8; 20],
    pub token: Vec<u8>,
    pub values: Option<Vec<Vec<u8>>>,
    pub nodes: Option<Vec<u8>>,
}
impl ToBencode for GetPeersResponse {
    fn to_bencode(&self) -> Bencode {
        let mut m = BTreeMap::new();
        m.set_bytes("id", self.id.to_vec());
        m.set_bytes("token", self.token.clone());
        m.set_list("values", &self.values, |v| Bencode::ByteString(v.clone()));

        if let Some(ref n) = self.nodes {
            m.set_bytes("nodes", n.clone());
        }

        Bencode::Dict(m)
    }
}
impl FromBencode for GetPeersResponse {
    type Err = String;
    fn from_bencode(b: &Bencode) -> Result<Self, String> {
        let m = unwrap_dict(b)?;
        Ok(GetPeersResponse {
            id: m.get_array("id")?,
            token: m.get_bytes("token")?,
            values: m.get_list("values", true, |item| match item {
                Bencode::ByteString(bytes) => Ok(bytes),
                _ => Err("Values be byte strings".to_owned()),
            })?,
            nodes: m.get_bytes("nodes").ok(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct AnnounceRequest {
    pub id: [u8; 20],
    pub info_hash: [u8; 20],
    pub port: u16,
    pub token: Vec<u8>,
}
impl ToBencode for AnnounceRequest {
    fn to_bencode(&self) -> Bencode {
        let mut m = BTreeMap::new();
        m.set_bytes("id", self.id.to_vec());
        m.set_bytes("info_hash", self.info_hash.to_vec());
        m.set_num("port", self.port as i64);
        m.set_bytes("token", self.token.clone());
        Bencode::Dict(m)
    }
}
impl FromBencode for AnnounceRequest {
    type Err = String;
    fn from_bencode(b: &Bencode) -> Result<Self, String> {
        let m = unwrap_dict(b)?;
        let id = m.get_array("id")?;
        let info_hash = m.get_array("info_hash")?;
        let port = m.get_num("port")? as u16;
        Ok(AnnounceRequest { id, info_hash, port, token: m.get_bytes("token")? })
    }
}

#[derive(Debug, Clone)]
pub struct AnnounceResponse {
    pub id: [u8; 20],
}
impl ToBencode for AnnounceResponse {
    fn to_bencode(&self) -> Bencode {
        let mut m = BTreeMap::new();
        m.set_bytes("id", self.id.to_vec());
        Bencode::Dict(m)
    }
}
impl FromBencode for AnnounceResponse {
    type Err = String;
    fn from_bencode(b: &Bencode) -> Result<Self, String> {
        let m = unwrap_dict(b)?;
        Ok(AnnounceResponse { id: m.get_array("id")? })
    }
}

#[inline(always)]
pub fn serialize_nodes_compact(nodes: Vec<Node>) -> Vec<u8> {
    let mut result = Vec::with_capacity(nodes.len() * 26);
    for node in nodes {
        if let SocketAddr::V4(addr_v4) = node.address {
            result.extend_from_slice(&node.id);
            result.extend_from_slice(&addr_v4.ip().octets());
            result.extend_from_slice(&addr_v4.port().to_be_bytes());
        }
    }
    result
}

#[inline(always)]
pub fn unserialize_nodes_compact(compact_nodes: &[u8]) -> Vec<Node> {
    let num_nodes = compact_nodes.len() / 26;
    let mut nodes = Vec::with_capacity(num_nodes);
    let mut chunk_idx = 0;

    while chunk_idx + 26 <= compact_nodes.len() {
        let mut id = [0u8; 20];
        id.copy_from_slice(&compact_nodes[chunk_idx..chunk_idx + 20]);

        let ip = Ipv4Addr::new(
            compact_nodes[chunk_idx + 20],
            compact_nodes[chunk_idx + 21],
            compact_nodes[chunk_idx + 22],
            compact_nodes[chunk_idx + 23],
        );
        let port = u16::from_be_bytes([compact_nodes[chunk_idx + 24], compact_nodes[chunk_idx + 25]]);

        nodes.push(Node { id, address: SocketAddr::new(IpAddr::V4(ip), port), last_seen: Instant::now() });

        chunk_idx += 26;
    }
    nodes
}

#[inline(always)]
pub fn serialize_address_compact(address: &SocketAddr) -> [u8; 6] {
    let mut raw_bytes = [0u8; 6];
    if let SocketAddr::V4(addr_v4) = address {
        raw_bytes[..4].copy_from_slice(&addr_v4.ip().octets());
        raw_bytes[4..6].copy_from_slice(&addr_v4.port().to_be_bytes());
    }
    raw_bytes
}

#[inline(always)]
pub fn unserialize_address_compact(compact_bytes: &[u8]) -> Result<SocketAddr, String> {
    if compact_bytes.len() != 6 {
        return Err("slice must be exactly 6 bytes.".to_owned());
    }
    let ip = Ipv4Addr::new(compact_bytes[0], compact_bytes[1], compact_bytes[2], compact_bytes[3]);
    let port = u16::from_be_bytes([compact_bytes[4], compact_bytes[5]]);
    Ok(SocketAddr::new(IpAddr::V4(ip), port))
}

#[inline(always)]
pub fn unserialize_values_compact(compact_values: &[Vec<u8>]) -> Vec<SocketAddr> {
    let mut addresses = Vec::with_capacity(compact_values.len());

    for value_bytes in compact_values {
        if value_bytes.len() == 6 {
            let ip = Ipv4Addr::new(value_bytes[0], value_bytes[1], value_bytes[2], value_bytes[3]);
            let port = u16::from_be_bytes([value_bytes[4], value_bytes[5]]);
            addresses.push(SocketAddr::new(IpAddr::V4(ip), port));
        }
    }
    addresses
}

pub trait DhtMessage: ToBencode + FromBencode + Send + Sync + 'static {
    type Response: FromBencode + ToBencode + Send + Sync + 'static;

    const METHOD: &'static [u8];
    const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1500);
}

impl DhtMessage for GetPeersRequest {
    type Response = GetPeersResponse;
    const METHOD: &'static [u8] = b"get_peers";
}

impl DhtMessage for FindNodeRequest {
    type Response = FindNodeResponse;
    const METHOD: &'static [u8] = b"find_node";
}

impl DhtMessage for PingPayload {
    type Response = PingPayload;
    const METHOD: &'static [u8] = b"ping";
}

impl DhtMessage for AnnounceRequest {
    type Response = AnnounceResponse;
    const METHOD: &'static [u8] = b"announce_peer";
}
