use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use pyo3::pymethods;
use pyo3::types::{PyAnyMethods, PyDict, PyDictMethods};
use pyo3::{pyclass, Py, PyAny};
use pyo3::{Bound, PyResult, Python};

use crate::community::routing::peer::PeerFlag;
use crate::InvalidAddressError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelSettings {
    pub prefix: Vec<u8>,
    pub prefixes: Vec<Vec<u8>>,
    pub min_circuits: u8,
    pub max_circuits: u8,
    pub max_joined_circuits: u16,
    pub max_relay_early: u8,
    // Maximum number of seconds before a circuit is considered inactive (and is removed)
    pub max_time_inactive: u32,
    // Maximum number of seconds total circuit creation is allowed to take.
    pub max_time_extending: u8,
    // Maximum number of seconds that a circuit should exist
    pub max_time: u32,
    pub max_traffic: u64,
    // Maximum number of seconds adding a single hop to a circuit is allowed to take.
    pub next_hop_timeout: u8,
    pub peer_flags: HashSet<PeerFlag>,
    pub exit_addr: SocketAddr,
    pub default_remotes: HashMap<u8, SocketAddr>,

    pub swarm_lookup_interval: u64,
    pub swarm_connection_limit: usize,
}

impl Default for TunnelSettings {
    fn default() -> Self {
        Self {
            prefix: vec![0; 22],
            prefixes: vec![],
            min_circuits: 3,
            max_circuits: 8,
            max_joined_circuits: 100,
            max_relay_early: 8,
            max_time_inactive: 20,
            max_time_extending: 20,
            max_time: 3600,
            max_traffic: 10 * 1024 * 1024 * 1024,
            next_hop_timeout: 10,
            peer_flags: [PeerFlag::Relay, PeerFlag::SpeedTest].into_iter().collect(),
            exit_addr: "[::]:0".parse().unwrap(),
            default_remotes: HashMap::new(),
            swarm_lookup_interval: 300,
            swarm_connection_limit: 15,
        }
    }
}

impl TunnelSettings {
    pub fn new() -> Self {
        Self::default()
    }
}

#[pyclass(name = "TunnelSettings", from_py_object)]
#[derive(Clone)]
pub struct PyTunnelSettings {
    #[pyo3(get, set)]
    pub prefix: Vec<u8>,
    #[pyo3(get, set)]
    pub prefixes: Vec<Vec<u8>>,
    #[pyo3(get, set)]
    pub min_circuits: u8,
    #[pyo3(get, set)]
    pub max_circuits: u8,
    #[pyo3(get, set)]
    pub max_joined_circuits: u16,
    #[pyo3(get, set)]
    pub max_relay_early: u8,
    #[pyo3(get, set)]
    pub max_time_inactive: u32,
    #[pyo3(get, set)]
    pub max_time_extending: u8,
    #[pyo3(get, set)]
    pub max_time: u32,
    #[pyo3(get, set)]
    pub max_traffic: u64,
    #[pyo3(get, set)]
    pub next_hop_timeout: u8,

    pub peer_flags: HashSet<PeerFlag>,
    pub exit_addr: SocketAddr,
    pub default_remotes: HashMap<u8, SocketAddr>,

    #[pyo3(get, set)]
    pub swarm_lookup_interval: u64,
    #[pyo3(get, set)]
    pub swarm_connection_limit: usize,
}

impl Default for PyTunnelSettings {
    fn default() -> Self {
        Self::from_native(&TunnelSettings::default())
    }
}

#[pymethods]
impl PyTunnelSettings {
    #[new]
    pub fn new() -> Self {
        let native = TunnelSettings::new();
        Self::from_native(&native)
    }

    #[setter(prefix)]
    pub fn set_prefix(&mut self, prefix: Vec<u8>) -> PyResult<()> {
        if prefix.len() != 22 {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Invalid prefix (expected 22 bytes, got {}).",
                prefix.len()
            )));
        }
        self.prefix = prefix;
        Ok(())
    }

    #[getter]
    pub fn peer_flags(&self) -> Vec<u16> {
        self.peer_flags.iter().map(|&f| f as u16).collect()
    }

    #[setter(peer_flags)]
    pub fn set_peer_flags(&mut self, raw_flags: std::collections::HashSet<u16>) {
        self.peer_flags = raw_flags
            .into_iter()
            .filter_map(|f| match f {
                1 => Some(PeerFlag::Relay),
                2 => Some(PeerFlag::ExitBt),
                4 => Some(PeerFlag::ExitIpv8),
                8 => Some(PeerFlag::SpeedTest),
                32768 => Some(PeerFlag::ExitHttp),
                _ => None,
            })
            .collect();
    }

    #[getter]
    pub fn exit_addr(&self) -> String {
        self.exit_addr.to_string()
    }

    #[setter(exit_addr)]
    pub fn set_exit_addr(&mut self, addr_str: String) -> PyResult<()> {
        self.exit_addr =
            addr_str.parse::<SocketAddr>().map_err(|e| InvalidAddressError::new_err(e.to_string()))?;
        Ok(())
    }

    #[getter]
    pub fn default_remotes(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let dict = PyDict::new(py);
        for (&hops, addr) in &self.default_remotes {
            dict.set_item(hops, addr.to_string())?;
        }
        Ok(dict.into_any().unbind())
    }

    #[setter(default_remotes)]
    pub fn set_default_remotes(&mut self, dict: &Bound<'_, PyDict>) -> PyResult<()> {
        let mut new_remotes = HashMap::new();
        for item_res in dict.items().try_iter()? {
            let item = item_res?;
            let (hops, addr_str) = item.extract::<(u8, String)>()?;
            let addr =
                addr_str.parse::<SocketAddr>().map_err(|e| InvalidAddressError::new_err(e.to_string()))?;
            new_remotes.insert(hops, addr);
        }
        self.default_remotes = new_remotes;
        Ok(())
    }
}

impl PyTunnelSettings {
    pub fn into_native(&self) -> TunnelSettings {
        TunnelSettings {
            prefix: self.prefix.clone(),
            prefixes: self.prefixes.clone(),
            min_circuits: self.min_circuits.clone(),
            max_circuits: self.max_circuits.clone(),
            max_joined_circuits: self.max_joined_circuits,
            max_relay_early: self.max_relay_early,
            max_time_inactive: self.max_time_inactive,
            max_time_extending: self.max_time_extending,
            max_time: self.max_time,
            max_traffic: self.max_traffic,
            next_hop_timeout: self.next_hop_timeout,
            peer_flags: self.peer_flags.clone(),
            exit_addr: self.exit_addr,
            default_remotes: self.default_remotes.clone(),
            swarm_lookup_interval: self.swarm_lookup_interval.clone(),
            swarm_connection_limit: self.swarm_connection_limit.clone(),
        }
    }

    pub fn from_native(native: &TunnelSettings) -> Self {
        PyTunnelSettings {
            prefix: native.prefix.clone(),
            prefixes: native.prefixes.clone(),
            min_circuits: native.min_circuits.clone(),
            max_circuits: native.max_circuits.clone(),
            max_joined_circuits: native.max_joined_circuits,
            max_relay_early: native.max_relay_early,
            max_time_inactive: native.max_time_inactive,
            max_time_extending: native.max_time_extending,
            max_time: native.max_time,
            max_traffic: native.max_traffic,
            next_hop_timeout: native.next_hop_timeout,
            peer_flags: native.peer_flags.clone(),
            exit_addr: native.exit_addr,
            default_remotes: native.default_remotes.clone(),
            swarm_lookup_interval: native.swarm_lookup_interval.clone(),
            swarm_connection_limit: native.swarm_connection_limit.clone(),
        }
    }
}
