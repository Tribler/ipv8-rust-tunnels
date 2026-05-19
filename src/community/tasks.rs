use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use rand::seq::{IndexedRandom, IteratorRandom, SliceRandom};
use tokio::time::sleep;

use crate::community::routing::circuit::{Circuit, CircuitState, CircuitType, Hop};
use crate::community::routing::peer::PeerFlag;
use crate::community::routing::table::RoutingTarget;
use crate::community::serialization::{CreatePayload, DestroyPayload, DestroyReason, PingPayload, VarLenH};
use crate::community::socks5::Socks5Server;
use crate::community::tunnels::TunnelCommunity;
use crate::crypto::keys::PrivateKey;
use crate::dht::engine::DHTWrapper;
use crate::peer::Peer;
use crate::util;

impl TunnelCommunity {
    pub fn start(&self) {
        self.start_circuit_manager();
        self.start_ping();
    }

    pub fn start_circuit_manager(&self) {
        let rt_base = self.rt.clone();
        let tunnels = self.self_handle.get().expect("Self handle uninitialized").clone();

        self.rt.task_manager.spawn_interval("do_circuits", Duration::from_secs(30), true, move || {
            let rt_clone = rt_base.clone();
            let tunnels_clone = tunnels.clone();

            async move {
                let circuits_needed = tunnels_clone.calculate_circuits_needed();
                let circuits_guard = rt_clone.circuits.load();
                let mut create_tasks = tokio::task::JoinSet::new();

                for (circuit_length, target_count) in circuits_needed {
                    let current_count = circuits_guard
                        .values()
                        .filter(|c| c.goal_hops == circuit_length && c.state() != CircuitState::Closing)
                        .count() as u8;

                    let num_to_build = target_count.saturating_sub(current_count);
                    if num_to_build == 0 {
                        continue;
                    }

                    info!("Want {} more data circuits of length {}", num_to_build, circuit_length);

                    for _ in 0..num_to_build {
                        let tunnels_clone_task = tunnels_clone.clone();
                        create_tasks.spawn(async move {
                            if tunnels_clone_task
                                .create_circuit(
                                    circuit_length,
                                    CircuitType::Data,
                                    Some(HashSet::from([PeerFlag::ExitBt])),
                                    None,
                                    None,
                                )
                                .await
                                .is_err()
                            {
                                info!("Circuit creation failed: no first hops available");
                            }
                        });
                    }
                }

                while let Some(_) = create_tasks.join_next().await {}
                tunnels_clone.do_remove().await;
            }
        });
    }

    fn calculate_circuits_needed(&self) -> HashMap<u8, u8> {
        let settings = self.rt.settings.load();
        let min_circuits = settings.min_circuits as u8;
        let max_circuits = settings.max_circuits as u8;

        let mut circuits_needed: HashMap<u8, u8> = HashMap::new();
        let servers = self.socks_servers.load();
        for server in servers.values() {
            let num_circuits = 2 * (server.associates.lock().unwrap().len() as u8);
            if num_circuits == 0 {
                continue;
            }

            let current_target = circuits_needed.entry(server.hops).or_insert(min_circuits);
            *current_target = (*current_target).max(num_circuits).min(max_circuits);
        }

        circuits_needed
    }

    pub async fn create_circuit(
        &self,
        goal_hops: u8,
        ctype: CircuitType,
        flags: Option<HashSet<PeerFlag>>,
        required_exit: Option<Peer>,
        infohash: Option<Vec<u8>>,
    ) -> Result<Arc<Circuit>, String> {
        info!("Creating circuit length {} (type: {:?})", goal_hops, ctype);
        let mut req_exit = if required_exit.is_some() {
            required_exit.clone()
        } else if ctype == CircuitType::IPSeeder && required_exit.is_none() {
            self.select_exit(ctype.clone(), None)
        } else {
            self.select_exit(ctype.clone(), flags.as_ref())
        };
        let mut first_hops = Vec::new();

        if goal_hops == 1 {
            req_exit = req_exit.or_else(|| self.select_exit(ctype.clone(), flags.as_ref()));
            first_hops.push(req_exit.clone().ok_or_else(|| "no exit available for first hop".to_owned())?);
        } else {
            let mut candidates: Vec<Peer> = self
                .rt
                .circuits
                .load()
                .values()
                .filter(|c| c.circuit_type == ctype)
                .filter_map(|c| c.first_hop().map(|h| h.peer.clone()))
                .collect();

            // Note that peers that are both relay and exit are in the list twice.
            // This will lower the likelihood that these peers are picked as first hop.
            candidates.extend(self.peer_cache.peers(&HashSet::from([PeerFlag::Relay])));
            candidates.extend(self.peer_cache.peers(&HashSet::from([PeerFlag::Relay, PeerFlag::ExitBt])));
            candidates.shuffle(&mut rand::rng());

            // Build a list of possible first hops, with the least frequently used hops first.
            let mut freqs = HashMap::new();
            for p in candidates {
                *freqs.entry(p).or_insert(0) += 1;
            }
            let mut sorted: Vec<_> = freqs.into_iter().collect();
            sorted.sort_by_key(|&(_, freq)| freq);

            first_hops.extend(sorted.into_iter().map(|(p, _)| p).filter(|p| Some(p) != req_exit.as_ref()));
        }

        let Some((next_peer, flags)) = first_hops
            .iter()
            .filter_map(|p| self.peer_cache.get_flags(p).map(|f| (p.clone(), f)))
            .choose(&mut rand::rng())
        else {
            return Err("no known candidates available as first hop".to_owned());
        };

        let addr = &next_peer.address;
        let circuit_id = self.generate_circuit_id();
        let mut raw_circuit = Circuit::new(
            circuit_id,
            goal_hops,
            ctype.clone(),
            *addr,
            self.rt.settings.load().max_relay_early,
        );
        raw_circuit.infohash = infohash;
        if required_exit.is_some() {
            raw_circuit.required_exit = required_exit;
        }
        let circuit = Arc::new(raw_circuit);
        self.rt.insert_circuit(circuit_id, Arc::clone(&circuit));

        info!("Sending initial create for circuit {} (type: {:?}) to {}", circuit_id, ctype, addr);

        let dh_secret =
            PrivateKey::generate("curve25519").map_err(|e| format!("error while generating key: {e}"))?;
        let dh_first_part =
            dh_secret.get_crypt_pk().map_err(|e| format!("error while getting crypt_pk: {e}"))?;

        let mut unverified = Hop::new(next_peer, flags);
        unverified.dh_first_part = Some(dh_first_part.clone());
        unverified.dh_secret = Some(dh_secret);
        circuit.set_unverified_hop(unverified);

        let identifier = self.request_cache.generate_identifier() as u16;
        let public_key = self.rt.runtime.get_my_public_key();
        let payload = CreatePayload {
            circuit_id: circuit.circuit_id,
            identifier,
            node_public_key: VarLenH { data_len: public_key.len() as u16, data: public_key },
            key: VarLenH { data_len: dh_first_part.len() as u16, data: dh_first_part },
        };

        info!("Sending create for circuit {}", circuit.circuit_id);
        if let Err(e) = self.rt.send_cell(&payload, Some(circuit.peer)).await {
            error!("Failed to send inital create to {:?}: {}", circuit.peer, e);
        }

        Ok(circuit)
    }

    pub async fn create_circuit_with_retry(
        &self,
        goal_hops: u8,
        ctype: CircuitType,
        flags: Option<HashSet<PeerFlag>>,
        required_exit: Option<Peer>,
        infohash: Option<Vec<u8>>,
    ) -> Result<Arc<Circuit>, String> {
        let (mut attempts, max_attempts, mut backoff) = (0, 5, 100);

        loop {
            attempts += 1;

            if let Ok(circuit) = self
                .create_circuit(
                    goal_hops,
                    ctype.clone(),
                    flags.clone(),
                    required_exit.clone(),
                    infohash.clone(),
                )
                .await
            {
                let circuit_id = circuit.circuit_id;
                match tokio::time::timeout(Duration::from_secs(2), circuit.ready.result()).await {
                    Ok(Ok(())) => {
                        info!("Circuit {} is ready (attempts={})!", circuit_id, attempts);
                        return Ok(circuit);
                    }
                    Ok(Err(e)) => warn!("Circuit {} error: {}", circuit_id, e),
                    Err(_) => warn!("Circuit {} timeout", circuit_id),
                }
                self.rt.remove_circuit(circuit_id);
            }

            if attempts >= max_attempts {
                return Err(format!("Exceeded limit of {} circuit creation attempts.", max_attempts));
            }

            tokio::time::sleep(Duration::from_millis(backoff)).await;
            backoff = (backoff * 2).min(1000);
        }
    }

    pub fn generate_circuit_id(&self) -> u32 {
        let mut circuit_id: u32 = rand::random();

        let circuits_guard = self.rt.circuits.load();
        while circuits_guard.contains_key(&circuit_id) || circuit_id == 0 {
            circuit_id = rand::random();
        }
        circuit_id
    }

    pub fn select_exit(&self, ctype: CircuitType, flags: Option<&HashSet<PeerFlag>>) -> Option<Peer> {
        let mut rng = rand::rng();
        let pool = if let Some(f) = flags {
            self.peer_cache.peers(f)
        } else {
            match ctype {
                CircuitType::Data => self.peer_cache.peers(&HashSet::from([PeerFlag::ExitBt])),
                CircuitType::IPSeeder => vec![
                    HashSet::from([PeerFlag::ExitBt]),
                    HashSet::from([PeerFlag::ExitIpv8]),
                    HashSet::from([PeerFlag::Relay]),
                ]
                .into_iter()
                .find_map(|f| {
                    let p = self.peer_cache.peers(&f);
                    (!p.is_empty()).then_some(p)
                })
                .unwrap_or_default(),
                _ => vec![HashSet::from([PeerFlag::Relay]), HashSet::from([PeerFlag::ExitBt])]
                    .into_iter()
                    .find_map(|f| {
                        let p = self.peer_cache.peers(&f);
                        (!p.is_empty()).then_some(p)
                    })
                    .unwrap_or_default(),
            }
        };
        pool.choose(&mut rng).cloned()
    }

    pub async fn do_remove(&self) {
        let now = util::get_time();
        let settings = self.rt.settings.load();

        let max_time_inactive = settings.max_time_inactive as u64;
        let max_time_extending = settings.max_time_extending as u64;
        let max_traffic = settings.max_traffic as u64;
        let max_time = settings.max_time as u64;

        let mut processed_relays = HashSet::new();
        let mut processed_rvs = HashSet::new();

        for (id, circuit) in self.rt.circuits.load().iter() {
            if circuit.state() == CircuitState::Closing {
                self.rt.remove_circuit(circuit.circuit_id);
                continue;
            }
            let last_received = circuit.stats.last_received.load(Ordering::Relaxed);
            let bytes_up = circuit.stats.bytes_up.load(Ordering::Relaxed);
            let bytes_down = circuit.stats.bytes_down.load(Ordering::Relaxed);

            let is_inactive = circuit.state() == CircuitState::Ready
                && now.saturating_sub(max_time_inactive) > last_received;
            let is_stalled = circuit.state() == CircuitState::Extending
                && now.saturating_sub(max_time_extending) > circuit.creation_time;
            let is_too_old = now.saturating_sub(max_time) > circuit.creation_time;
            let traffic_exceeded = (bytes_up + bytes_down) > max_traffic;

            if is_inactive || is_stalled || is_too_old || traffic_exceeded {
                if is_inactive {
                    info!("Closing circuit {}: no activity", id);
                } else if is_stalled {
                    info!("Closing circuit {}: not ready in time", id);
                } else if is_too_old {
                    info!("Closing circuit {}: too old", id);
                } else if traffic_exceeded {
                    info!("Closing circuit {}: traffic limit exceeded", id);
                }
                self.remove_route(*id, DestroyReason::Unknown, true).await;
            }
        }

        let relays_guard = self.rt.relays.load();
        for (id, relay) in relays_guard.iter() {
            if !processed_relays.insert(relay.circuit_id_fw) {
                continue;
            }

            let last_received = relay.stats.last_received.load(Ordering::Relaxed);
            let bytes_up = relay.stats.bytes_up.load(Ordering::Relaxed);
            let bytes_down = relay.stats.bytes_down.load(Ordering::Relaxed);

            let is_inactive = last_received < now.saturating_sub(max_time);
            let traffic_exceeded = (bytes_up + bytes_down) > max_traffic;

            if is_inactive || traffic_exceeded {
                if is_inactive {
                    info!("Removing relay {}: no activity", id);
                } else if traffic_exceeded {
                    info!("Removing relay {}: traffic limit exceeded", id);
                }
                self.remove_route(*id, DestroyReason::Unknown, true).await;
            }
        }

        let rvs_guard = self.rt.rendezvous.load();
        for (id, rv) in rvs_guard.iter() {
            if !processed_rvs.insert(rv.circuit_id_dl) {
                continue;
            }

            let last_received = rv.stats.last_received.load(Ordering::Relaxed);
            let bytes_up = rv.stats.bytes_up.load(Ordering::Relaxed);
            let bytes_down = rv.stats.bytes_down.load(Ordering::Relaxed);

            let is_inactive = last_received < now.saturating_sub(max_time);
            let traffic_exceeded = (bytes_up + bytes_down) > max_traffic;

            if is_inactive || traffic_exceeded {
                if is_inactive {
                    info!("Removing rendezvous {}: no activity", id);
                } else if traffic_exceeded {
                    info!("Removing rendezvous {}: traffic limit exceeded", id);
                }
                self.remove_route(*id, DestroyReason::Unknown, true).await;
            }
        }

        let exits_guard = self.rt.exits.load();
        for (id, exit) in exits_guard.iter() {
            let last_received = exit.stats.last_received.load(Ordering::Relaxed);
            let bytes_up = exit.stats.bytes_up.load(Ordering::Relaxed);
            let bytes_down = exit.stats.bytes_down.load(Ordering::Relaxed);

            let is_inactive = last_received < now.saturating_sub(max_time_inactive);
            let is_too_old = exit.creation_time < now.saturating_sub(max_time);
            let traffic_exceeded = (bytes_up + bytes_down) > max_traffic;

            if is_inactive || is_too_old || traffic_exceeded {
                if is_inactive {
                    info!("Removing exit socket {}: no activity", exit.circuit_id);
                } else if is_too_old {
                    info!("Removing exit socket {}: too old", exit.circuit_id);
                } else if traffic_exceeded {
                    info!("Removing exit socket {}: traffic limit exceeded", exit.circuit_id);
                }
                self.remove_route(*id, DestroyReason::Unknown, true).await;
            }
        }

        // PeerCache get synced with the IPv8 peers, and doesn't need filtering.
    }

    pub fn start_ping(&self) {
        let rt_base = self.rt.clone();
        let cache_base = self.request_cache.clone();

        self.rt.task_manager.spawn_interval("do_ping", Duration::from_millis(7500), true, move || {
            // Clone handles for every interval.
            let rt_clone = rt_base.clone();
            let request_cache = cache_base.clone();

            async move {
                let targets: Vec<_> = rt_clone
                    .circuits
                    .load()
                    .values()
                    .filter(|c| c.state() == CircuitState::Ready || c.state() == CircuitState::Extending)
                    .filter_map(|c| c.first_hop().map(|h| (c.circuit_id, h.address().clone())))
                    .collect();

                for (circuit_id, hop_address) in targets {
                    let identifier: u16 = rand::random();
                    request_cache.add_identifier("PingRequestCache".to_owned(), identifier, Some(5), None);

                    let ping = PingPayload { circuit_id, identifier };

                    if let Err(e) = rt_clone.send_cell(&ping, None).await {
                        error!("Failed to send ping to {:?}: {}", hop_address, e);
                        request_cache.pop("PingRequestCache", identifier);
                    }
                }
            }
        });
    }

    pub async fn shutdown(&self) {
        info!("Shutting down TunnelCommunity...");

        if let Some(dht) = self.hs_state.dht.swap(None) {
            dht.shutdown().await;
        }

        let circuits = self.rt.circuits.swap(Arc::new(HashMap::new()));
        let relays = self.rt.relays.swap(Arc::new(HashMap::new()));
        let exits = self.rt.exits.swap(Arc::new(HashMap::new()));

        for (circuit_id, _circuit) in circuits.iter() {
            self.send_destroy(*circuit_id, DestroyReason::Shutdown).await;
        }

        for (circuit_id, _relay) in relays.iter() {
            self.send_destroy(*circuit_id, DestroyReason::Shutdown).await;
        }

        for (circuit_id, exit) in exits.iter() {
            exit.token.cancel();
            self.send_destroy(*circuit_id, DestroyReason::Shutdown).await;
        }

        info!(
            "TunnelCommunity shutdown completed (cleared routing table: {} / {} / {}).",
            circuits.len(),
            relays.len(),
            exits.len()
        );
    }

    pub async fn remove_route(&self, id: u32, reason: DestroyReason, send_destroy: bool) {
        if send_destroy {
            self.send_destroy(id, reason).await;
        }

        if let Some(target) = self.rt.get_routing_object(id) {
            match target {
                RoutingTarget::Circuit(c) => {
                    c.closing.store(true, std::sync::atomic::Ordering::Relaxed);
                    let rt = self.rt.clone();
                    let hs_state = self.hs_state.clone();
                    self.rt.task_manager.spawn("circuit-remove-pending", async move {
                        sleep(Duration::from_secs(5)).await;
                        rt.remove_circuit(id);
                        hs_state.remove_broken_ips(id);
                    });
                    info!("Removed circuit {id} (reason={:?})", reason);
                }
                RoutingTarget::Exit(e) => {
                    e.token.cancel();
                    self.rt.remove_exit(id);
                    info!("Removed exit {id} (reason={:?})", reason);
                }
                RoutingTarget::Relay(r) => {
                    let fw_id = r.circuit_id_fw;
                    let bw_id = r.circuit_id_bw;
                    self.rt.remove_relay(fw_id);
                    self.rt.remove_relay(bw_id);
                    info!("Removed relay (fw={fw_id}, bw={bw_id}) (reason={:?})", reason);
                }
                RoutingTarget::Rendezvous(rv) => {
                    let dl_id = rv.circuit_id_dl;
                    let sd_id = rv.circuit_id_sd;
                    self.rt.rendezvous.rcu(|active_map| {
                        let mut new_map = (**active_map).clone();
                        new_map.remove(&dl_id);
                        new_map.remove(&sd_id);
                        new_map
                    });
                    info!("Removed rendezvous (dl={dl_id}, sd={sd_id}) (reason={:?})", reason);
                }
            }
        } else {
            warn!("Failed to remove unknown circuit ID {id}");
        }
    }

    pub async fn send_destroy(&self, circuit_id: u32, reason: DestroyReason) {
        let payload = DestroyPayload { circuit_id, reason: reason as u16 };

        match self.rt.send_cell(&payload, None).await {
            Ok(_) => debug!("Sending destroy for circuit {}", circuit_id),
            Err(e) => error!("error sending destroy: {}", e),
        };
    }

    pub async fn start_socks5_server(&self, port: u16, hops: u8) -> Result<u16, String> {
        let addr: SocketAddr =
            format!("127.0.0.1:{}", port).parse().map_err(|e| format!("invalid address: {e}"))?;

        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let cloned_rt = self.rt.clone();
        let request_cache = self.request_cache.clone();
        let socks_servers_clone = self.socks_servers.clone();

        let task_name = format!("socks_server_{}", hops);
        self.rt.task_manager.spawn(&task_name, async move {
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("TCP listener couldn't be created: {}", e);
                    return;
                }
            };
            let listen_addr = listener.local_addr().unwrap();
            info!("Socks5 server (hops={}) listening on: {:?}", hops, listen_addr);
            let mut server = Socks5Server::new(cloned_rt, request_cache, hops);
            socks_servers_clone.rcu(|active_map| {
                let mut new_map = (**active_map).clone();
                new_map.insert(listen_addr, server.clone());
                new_map
            });

            let _ = addr_tx.send(listen_addr);
            let _ = server.listen_forever(listener).await;
        });

        let addr = addr_rx.recv().map_err(|_| "failed to get SOCKS5 port".to_owned())?;

        if hops == 1 {
            self.start_dht(addr);
        }

        Ok(addr.port())
    }

    pub fn start_dht(&self, proxy_addr: SocketAddr) {
        let tunnels = self.self_handle.get().expect("Self handle uninitialized").clone();

        self.rt.task_manager.spawn("init_dht", async move {
            let dht_wrapper = match DHTWrapper::new(proxy_addr, tunnels.rt.task_manager.clone()).await {
                Ok(w) => Arc::new(w),
                Err(e) => {
                    error!("Failed to start DHT: {}", e);
                    return;
                }
            };

            dht_wrapper.start();
            tunnels.hs_state.dht.store(Some(dht_wrapper));
        });
    }
}
