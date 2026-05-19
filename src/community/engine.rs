use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};

use arc_swap::{ArcSwap, ArcSwapOption};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyTuple};
use pyo3::IntoPyObjectExt;

use crate::community::hiddenservices::{HiddenServiceState, PySwarm};
use crate::community::routing::circuit::{PyCircuitStats, PyHopStats};
use crate::community::routing::exit::PyExitStats;
use crate::community::routing::peer::{PeerCache, PeerFlag};
use crate::community::routing::relay::PyRelayStats;
use crate::community::routing::rendezvous::PyRendezvousStats;
use crate::community::routing::table::RoutingTable;
use crate::community::serialization::Address;
use crate::community::settings::PyTunnelSettings;
use crate::community::socks5::Socks5Server;
use crate::community::{Community, TunnelCommunity};
use crate::crypto::keys::{PublicKey, PyPrivateKey};
use crate::parse_address;
use crate::peer::{CachedNode, Peer};
use crate::request_cache::RequestCache;
use crate::task_manager::TaskManager;
use crate::transport::endpoint::Endpoint;
use crate::transport::listener::PacketListener;

#[pyclass(name = "TunnelEngine")]
pub struct PyTunnelEngine {
    pub community: ArcSwapOption<TunnelCommunity>,
    pub listener: ArcSwapOption<PacketListener>,
    pub socks_servers: Arc<ArcSwap<HashMap<SocketAddr, Socks5Server>>>,
}

#[pymethods]
impl PyTunnelEngine {
    #[new]
    pub fn new() -> Self {
        PyTunnelEngine {
            community: ArcSwapOption::empty(),
            listener: ArcSwapOption::empty(),
            socks_servers: Arc::new(arc_swap::ArcSwap::from_pointee(HashMap::new())),
        }
    }

    #[pyo3(signature = (py_endpoint, my_sk, config))]
    pub fn start(
        slf: PyRef<'_, PyTunnelEngine>,
        py_endpoint: Py<PyAny>,
        my_sk: &PyPrivateKey,
        config: &PyTunnelSettings,
        py: Python<'_>,
    ) -> PyResult<()> {
        // Remove the wrapper, if needed, and get the native Rust `Endpoint`
        let bound_obj = py_endpoint.into_bound(py);
        let native_bound = if bound_obj.hasattr("inner")? {
            bound_obj.getattr("inner")?
        } else {
            bound_obj
        };
        let mut endpoint = native_bound.extract::<PyRefMut<'_, Endpoint>>()?;

        let listener =
            endpoint.listener.as_ref().ok_or_else(|| PyRuntimeError::new_err("Endpoint is not open"))?;

        let tm_endpoint = endpoint
            .task_manager
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("TaskManager is not initialized"))?;

        let tx_outbound = endpoint.tx_outbound.as_ref().unwrap().clone();

        if slf.community.load().is_some() {
            return Err(PyRuntimeError::new_err("TunnelEngine has already been started!"));
        }

        // Binds the Tokio runtime to the current Python thread so background tasks can run safely.
        let runtime_handle = tm_endpoint.handle.clone();
        let _tokio_guard = runtime_handle.enter();
        let tm_engine = TaskManager::new(runtime_handle);

        let settings = Arc::new(arc_swap::ArcSwap::from_pointee(config.into_native()));
        let prefix: [u8; 22] = settings.load().prefix.clone().try_into().unwrap_or([0u8; 22]);
        let prefix_hex: String = prefix.iter().map(|b| format!("{:02X}", b)).collect();

        info!("Creating TunnelCommunity {} with flags: {:?}", prefix_hex, settings.load().peer_flags);

        // Using duck-typing to avoid making a mess of the function signature.
        let config_bound = config.clone().into_pyobject(py)?;
        let e2e_callback = config_bound.getattr("e2e_callback").ok().map(|item| item.unbind());

        let tunnel_community = Arc::new(TunnelCommunity {
            prefix,
            rt: RoutingTable::new(tx_outbound, my_sk.core.clone(), settings.clone(), tm_engine),
            request_cache: RequestCache::new(),
            peer_cache: PeerCache::new(),
            self_handle: OnceLock::new(),
            socks_servers: slf.socks_servers.clone(),
            local_addr: listener.local_addr(),
            hs_state: Arc::new(HiddenServiceState::new(e2e_callback)),
        });

        tunnel_community
            .self_handle
            .set(Arc::clone(&tunnel_community))
            .expect("Failed to set TunnelCommunity self_handle");

        let mut active_communities = listener.router().communities.load_full().as_ref().clone();
        active_communities.insert(prefix, Community::Tunnel(tunnel_community.clone()));
        listener.router().communities.store(Arc::new(active_communities));

        info!("Starting TunnelCommunity background tasks");
        TunnelCommunity::start(&tunnel_community);

        slf.listener.store(Some(listener.clone()));
        slf.community.store(Some(tunnel_community));

        let engine_py: Py<PyTunnelEngine> = slf.into_pyobject(py)?.extract()?;
        endpoint.engine = Some(engine_py);
        Ok(())
    }

    pub fn stop(&self, _py: Python, timeout_secs: u64) -> PyResult<()> {
        info!("Stopping tunnel engine...");

        if let Some(tunnel_community) = self.community.swap(None) {
            let tm_engine = tunnel_community.rt.task_manager.clone();
            let handle = tm_engine.handle.clone();

            info!("Stopping tunnel engine tasks...");
            handle.block_on(async move {
                tm_engine.shutdown(timeout_secs).await;
                tunnel_community.shutdown().await;
            });
        }
        self.socks_servers.store(Arc::new(HashMap::new()));
        info!("Tunnel engine shutdown completed");
        Ok(())
    }

    pub fn create_socks5_server(&self, port: u16, hops: u8) -> PyResult<u16> {
        let rt = self.get_rt()?;
        let community = self.get_community()?;

        let port = rt
            .task_manager
            .handle
            .block_on(async move { community.start_socks5_server(port, hops).await })
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))?;

        Ok(port)
    }

    pub fn set_udp_associate_default_remote(&self, address: &Bound<'_, PyTuple>, hops: u8) -> PyResult<()> {
        let rt = self.get_rt()?;
        let socket_addr = parse_address(address)?;
        let servers = self.socks_servers.load();
        for server in servers.values() {
            if server.hops != hops {
                continue;
            }
            for associate in server.associates.lock().unwrap().values() {
                if associate.socket.peer_addr().is_err() {
                    let socket = associate.socket.clone();
                    rt.task_manager.spawn("associate_connect", async move {
                        let _ = socket.connect(socket_addr).await;
                    });
                }
            }
        }
        Ok(())
    }

    pub fn get_associated_circuits(&self, port: u16, py: Python<'_>) -> PyResult<PyObject> {
        let rt = self.get_rt()?;
        let mut circuit_ids = Vec::new();

        for circuit in rt.circuits.load().values() {
            if let Some(socket) = circuit.socket.load().as_ref() {
                if let Ok(local_addr) = socket.local_addr() {
                    if local_addr.port() == port {
                        circuit_ids.push(circuit.circuit_id);
                    }
                }
            }
        }
        Ok(PyTuple::new(py, circuit_ids)?.into_any().unbind())
    }

    pub fn get_peers_for_circuit(&self, circuit_id: u32, py: Python<'_>) -> PyResult<PyObject> {
        let rt = self.get_rt()?;
        let mut result = Vec::new();

        let guard = rt.circuits.load();
        let hops = match guard.get(&circuit_id) {
            Some(circuit) => circuit.goal_hops,
            None => return Ok(PyList::new(py, result)?.into_any().unbind()),
        };
        drop(guard);

        let servers = self.socks_servers.load();
        for server in servers.values() {
            if server.hops != hops {
                continue;
            }

            for associate in server.associates.lock().unwrap().values() {
                for (addr, cid) in associate.addr_to_cid.lock().unwrap().iter() {
                    if *cid == circuit_id {
                        let (host, port) = match addr {
                            Address::V4(a) => (a.ip().to_string(), a.port()),
                            Address::V6(a) => (a.ip().to_string(), a.port()),
                            Address::DomainAddress(_, _) => {
                                (addr.hostname().unwrap_or_default(), addr.port())
                            }
                        };
                        let any_addr = vec![host.into_py_any(py)?, port.into_py_any(py)?];
                        result.push(PyTuple::new(py, any_addr)?.into_any().unbind());
                    }
                }
            }
        }
        Ok(PyList::new(py, result)?.into_any().unbind())
    }

    pub fn set_exit_address(&self, address: &Bound<'_, PyTuple>) -> PyResult<()> {
        let exit_addr = parse_address(address)?;
        let rt = self.get_rt()?;
        let mut new_settings = (**rt.settings.load()).clone();
        new_settings.exit_addr = exit_addr;
        info!("Set exit address: {:?}", new_settings.exit_addr);
        rt.settings.swap(Arc::new(new_settings));
        Ok(())
    }

    pub fn get_socks5_statistics(&self, py: Python<'_>) -> PyResult<PyObject> {
        let mut result = Vec::new();
        for (addr, server) in self.socks_servers.load().iter() {
            let item = PyDict::new(py);
            let _ = item.set_item("port", addr.port());
            let _ = item.set_item("hops", server.hops);
            let _ = item.set_item("associates", server.associates.lock().unwrap().len());
            result.push(item);
        }
        Ok(PyList::new(py, result)?.into_any().unbind())
    }

    #[pyo3(signature = ())]
    pub fn get_tunnel_statistics(&self, py: Python<'_>) -> PyResult<PyObject> {
        let result = PyDict::new(py);
        let rt = self.get_rt()?;
        let tunnels = self.get_community()?;

        let mut seen_relays = std::collections::HashSet::new();
        let mut seen_rvs = std::collections::HashSet::new();

        let circuits: Vec<_> = rt
            .circuits
            .load()
            .iter()
            .map(|(_, c)| {
                let hops = c.hops.load();
                let mut py_hops: Vec<_> = hops
                    .verified
                    .iter()
                    .map(|h| PyHopStats {
                        address: h.address().to_string(),
                        mid: h.mid().to_vec(),
                        public_key: h.public_key_bin(),
                        is_verified: true,
                        flags: h.flags.iter().map(|&f| f as u16).collect(),
                    })
                    .collect();

                if let Some(h) = &hops.unverified {
                    py_hops.push(PyHopStats {
                        address: h.address().to_string(),
                        mid: h.mid().to_vec(),
                        public_key: h.public_key_bin(),
                        is_verified: false,
                        flags: h.flags.iter().map(|&f| f as u16).collect(),
                    });
                }

                PyCircuitStats {
                    circuit_id: c.circuit_id,
                    goal_hops: c.goal_hops,
                    peer: c.peer.to_string(),
                    creation_time: c.creation_time,
                    state: c.state().to_string(),
                    circuit_type: c.circuit_type.to_string(),
                    data_ready: c.data_ready(),
                    hops: py_hops,
                    exit_flags: c.exit_flags(),
                    bytes_up: c.stats.bytes_up.load(Ordering::Relaxed),
                    bytes_down: c.stats.bytes_down.load(Ordering::Relaxed),
                    last_received: c.stats.last_received.load(Ordering::Relaxed),
                }
            })
            .collect();
        result.set_item("circuits", circuits)?;

        let relays: Vec<_> = rt
            .relays
            .load()
            .iter()
            .filter(|(_, r)| seen_relays.insert(r.circuit_id_fw))
            .map(|(_, r)| PyRelayStats {
                circuit_id_fw: r.circuit_id_fw,
                circuit_id_bw: r.circuit_id_bw,
                is_rendezvous: r.rendezvous_relay,
                bytes_up: r.stats.bytes_up.load(Ordering::Relaxed),
                bytes_down: r.stats.bytes_down.load(Ordering::Relaxed),
                creation_time: r.creation_time,
            })
            .collect();
        result.set_item("relays", relays)?;

        let rendezvous: Vec<_> = rt
            .rendezvous
            .load()
            .iter()
            .filter(|(_, rv)| seen_rvs.insert(rv.circuit_id_dl))
            .map(|(_, rv)| PyRendezvousStats {
                circuit_id_dl: rv.circuit_id_dl,
                circuit_id_sd: rv.circuit_id_sd,
                peer_dl: rv.peer_dl.to_string(),
                peer_sd: rv.peer_sd.to_string(),
                bytes_up: rv.stats.bytes_up.load(Ordering::Relaxed),
                bytes_down: rv.stats.bytes_down.load(Ordering::Relaxed),
                creation_time: rv.creation_time,
            })
            .collect();
        result.set_item("rendezvous", rendezvous)?;

        let exits: Vec<_> = rt
            .exits
            .load()
            .iter()
            .map(|(&id, exit)| PyExitStats {
                circuit_id: id,
                enabled: exit.socket.initialized(),
                bytes_up: exit.stats.bytes_up.load(Ordering::Relaxed),
                bytes_down: exit.stats.bytes_down.load(Ordering::Relaxed),
                creation_time: exit.creation_time,
                is_introduction: exit.is_introduction.load(Ordering::Relaxed),
                is_rendezvous: exit.is_rendezvous.load(Ordering::Relaxed),
            })
            .collect();
        result.set_item("exits", exits)?;

        let swarms: Vec<_> = tunnels
            .hs_state
            .swarms
            .load()
            .iter()
            .map(|(&info_hash, swarm)| PySwarm {
                info_hash,
                num_intro_points: swarm.get_intro_points().len(),
                num_seeders: swarm.get_num_seeders(),
                num_connections: swarm.get_num_connections(),
                num_connections_incomplete: swarm.get_num_connections_incomplete(),
                seeding: swarm.seeding.load(Ordering::Relaxed),
                last_lookup: swarm.last_lookup.load(Ordering::Relaxed),
                bytes_up: swarm.get_total_up(),
                bytes_down: swarm.get_total_down(),
            })
            .collect();
        result.set_item("swarms", swarms)?;

        Ok(result.into_any().unbind())
    }

    #[pyo3(signature = (config))]
    pub fn set_settings(&self, config: &PyTunnelSettings, _py: Python<'_>) -> PyResult<()> {
        let rt = self.get_rt()?;
        let old_prefix: Option<[u8; 22]> = rt.settings.load().prefix.clone().try_into().ok();
        let new_settings = config.into_native();

        info!("Updating tunnel settings: {:?}", new_settings);
        rt.settings.swap(Arc::new(new_settings));

        if let (Some(old), Ok(new)) = (old_prefix, rt.settings.load().prefix.clone().try_into()) {
            if let Ok(listener) = self.get_listener() {
                listener.router().update_prefix(&old, new);
            }
        }

        Ok(())
    }

    pub fn get_settings(&self, _py: Python<'_>) -> PyResult<PyTunnelSettings> {
        let rt = self.get_rt()?;
        let settings = rt.settings.load_full();
        Ok(PyTunnelSettings::from_native(&settings))
    }

    pub fn set_peers(&self, py_candidates: &Bound<'_, PyAny>) -> PyResult<()> {
        let community = self.get_community()?;
        let cache = &community.peer_cache;

        let py_dict = py_candidates.downcast::<PyDict>()?;
        let mut new_entries = Vec::with_capacity(py_dict.len());

        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

        for entry in py_dict.items().iter() {
            let (candidate, raw_flags_obj) = entry.extract::<(Bound<'_, PyAny>, Bound<'_, PyAny>)>()?;

            let py_address_obj = candidate.getattr("address")?;
            let target_address = match parse_address(&py_address_obj) {
                Ok(addr) => addr,
                Err(_) => continue,
            };

            let pub_key_obj = candidate.getattr("public_key")?;
            let pub_key_bytes: Vec<u8> = pub_key_obj.call_method0("key_to_bin")?.extract()?;
            let public_key = PublicKey::from_bytes(&pub_key_bytes)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let raw_flags = raw_flags_obj.downcast::<PyList>()?.extract::<Vec<u16>>()?;

            let mut flags = HashSet::new();
            for f in raw_flags {
                match f {
                    1 => flags.insert(PeerFlag::Relay),
                    2 => flags.insert(PeerFlag::ExitBt),
                    4 => flags.insert(PeerFlag::ExitIpv8),
                    8 => flags.insert(PeerFlag::SpeedTest),
                    32768 => flags.insert(PeerFlag::ExitHttp),
                    _ => continue,
                };
            }

            let peer = Peer { address: target_address, public_key, private_key: None };
            new_entries.push(CachedNode { peer, metadata: flags, last_seen: now });
        }

        info!("Replacing peercache ({})", new_entries.len());
        cache.replace_snapshot(new_entries);
        Ok(())
    }

    pub fn set_my_estimated_wan(&self, address: &Bound<'_, PyTuple>) -> PyResult<()> {
        let socket_addr = parse_address(address)?;
        let community = self.get_community()?;
        info!("Settings my estimated WAN: {}", socket_addr);
        community.rt.runtime.my_estimated_wan.store(Some(Arc::new(socket_addr)));
        Ok(())
    }

    pub fn run_speedtest(
        &self,
        circuit_id: u32,
        test_time: u16,
        request_size: u16,
        response_size: u16,
        target_rrt: u16,
        callback: PyObject,
        callback_interval: u16,
    ) -> PyResult<()> {
        let rt = self.get_rt()?;
        let stats = self.get_listener()?.stats();
        rt.task_manager.spawn(
            "speedtest",
            crate::community::speedtest::run_test(
                circuit_id,
                rt.clone(),
                test_time,
                request_size,
                response_size,
                target_rrt,
                callback,
                callback_interval,
                stats,
            ),
        );
        Ok(())
    }
}

impl PyTunnelEngine {
    pub fn get_rt(&self) -> PyResult<RoutingTable> {
        match self.community.load_full() {
            Some(community) => Ok(community.rt.clone()),
            None => Err(crate::NotOpenError::new_err("No routing table")),
        }
    }

    fn get_listener(&self) -> PyResult<Arc<PacketListener>> {
        match self.listener.load_full() {
            Some(listener) => Ok(listener),
            None => Err(crate::NotOpenError::new_err("No packet listener")),
        }
    }

    fn get_community(&self) -> PyResult<Arc<TunnelCommunity>> {
        match self.community.load_full() {
            Some(community) => Ok(community),
            None => Err(crate::NotOpenError::new_err("No community")),
        }
    }
}
