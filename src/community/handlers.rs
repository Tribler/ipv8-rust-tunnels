use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use deku::DekuContainerRead;
use rand::seq::IndexedRandom;
use rand::Rng;
use tokio::time::timeout;

use crate::community::routing::circuit::{Circuit, CircuitState, Hop, Hops};
use crate::community::routing::exit::ExitSocket;
use crate::community::routing::peer::PeerFlag;
use crate::community::routing::relay::Relay;
use crate::community::serialization::{
    unpack_cell_payload, unpack_signed_payload, Address, CandidatePayload, CellId, CreatePayload,
    CreatedPayload, DestroyPayload, ExtendPayload, ExtendedPayload, HTTPRequestPayload, HTTPResponsePayload,
    MessageId, PingPayload, PongPayload, Raw, TestRequestPayload, TestResponsePayload, VarLenH,
};
use crate::community::speedtest::TestMetric;
use crate::community::tunnels::TunnelCommunity;
use crate::crypto::cipher::{Direction, SessionKeys};
use crate::crypto::keys::{PrivateKey, PublicKey};
use crate::peer::Peer;
use crate::request_cache::CacheResult;
use crate::util::{send_tcp_request, Result};

pub struct CreateRequestCache {
    pub identifier: u16,
    pub fw_circuit_id: u32,
    pub fw_addr: SocketAddr,
    pub bw_circuit_id: u32,
}

impl TunnelCommunity {
    pub async fn on_message_core(
        &self,
        address: SocketAddr,
        msg_id: MessageId,
        buffer: &mut Vec<u8>,
    ) -> Result<()> {
        let circuit_id = u32::from_be_bytes(buffer[23..27].try_into().unwrap());

        match msg_id {
            MessageId::Destroy => self.on_destroy(address, circuit_id, buffer).await,
            _ => Ok(()),
        }
    }

    pub async fn on_cell_core(
        &self,
        address: SocketAddr,
        circuit_id: u32,
        cell_id: CellId,
        buffer: &mut Vec<u8>,
    ) -> crate::util::Result<()> {
        match cell_id {
            CellId::Create => self.on_create(address, circuit_id, buffer).await,
            CellId::Created => self.on_created(address, circuit_id, buffer).await,
            CellId::Extend => self.on_extend(address, circuit_id, buffer).await,
            CellId::Extended => self.on_extended(address, circuit_id, buffer).await,
            CellId::Ping => self.on_ping(address, circuit_id, buffer).await,
            CellId::Pong => self.on_pong(address, circuit_id, buffer).await,
            CellId::Destroy => self.on_destroy(address, circuit_id, buffer).await,
            CellId::TestRequest => self.on_test_request(address, circuit_id, buffer).await,
            CellId::TestResponse => self.on_test_response(address, circuit_id, buffer).await,
            CellId::HttpRequest => self.on_http_request(address, circuit_id, buffer).await,
            CellId::HttpResponse => self.on_http_response(address, circuit_id, buffer).await,
            _ => Ok(()),
        }
    }

    pub async fn on_create(&self, address: SocketAddr, circuit_id: u32, cell: &mut Vec<u8>) -> Result<()> {
        let settings = self.rt.settings.load();

        if settings.peer_flags.is_empty() {
            warn!("Ignoring create for circuit {}: node flags are disabled", circuit_id);
            return Ok(());
        }

        if self.request_cache.has("CreatedRequestCache", circuit_id) {
            warn!("Already have a request for circuit {}", circuit_id);
            return Ok(());
        }

        let total_active = self.rt.relays.load().len() + self.rt.exits.load().len();
        if settings.max_joined_circuits as usize <= total_active {
            warn!("Too many relays ({})", total_active);
            return Ok(());
        }

        let payload: CreatePayload = unpack_cell_payload(cell)?;
        info!("We joined circuit {} with neighbour {:?}", circuit_id, address);

        let my_sk_guard = self.rt.runtime.my_sk.load();
        let my_sk = my_sk_guard.as_ref().ok_or_else(|| "Missing private key".to_string())?;
        let (crypt_pk, auth, session_keys) = SessionKeys::generate_inbound(my_sk, &payload.key.data)?;
        let (peers_keys, _) = self.peer_cache.get_handshake_candidates();

        // Format: IPv8 varlenH-list
        let mut candidates_enc = CandidatePayload::from_candidates(peers_keys)?;
        session_keys
            .encrypt_in_place(&mut candidates_enc, Direction::Forward)
            .map_err(|e| format!("Failed to encrypt candidates: {}", e))?;

        let mut exit = ExitSocket::new(circuit_id);
        exit.peer = address.into();
        exit.keys.store(std::sync::Arc::new(vec![session_keys]));

        self.rt.insert_exit(circuit_id, Arc::new(exit));

        let auth_fixed: [u8; 32] =
            auth.as_slice()[..32].try_into().map_err(|e| format!("bad auth size: {e}"))?;

        let reply = CreatedPayload {
            circuit_id,
            identifier: payload.identifier,
            key: VarLenH { data_len: crypt_pk.len() as u16, data: crypt_pk },
            auth: auth_fixed,
            candidates_enc: Raw { data: candidates_enc },
        };

        self.rt.send_cell(&reply, None).await.map(|_| ())
    }

    pub async fn on_created(&self, _address: SocketAddr, circuit_id: u32, cell: &mut Vec<u8>) -> Result<()> {
        let payload: CreatedPayload = unpack_cell_payload(cell)?;

        // Are we an intermediate node?
        if self.request_cache.has("CreateRequestCache", payload.identifier) {
            let cache_res = self.request_cache.pop("CreateRequestCache", payload.identifier);

            let CacheResult::Identifier(Some(any_ptr)) = cache_res else {
                return Err("Empty cache data for CreateRequestCache".to_owned());
            };

            let Some(cache) = any_ptr.downcast_ref::<CreateRequestCache>() else {
                return Err("Failed to downcast to CreateRequestCache".to_owned());
            };

            info!("Got CREATED message forward as EXTENDED to origin.");

            let Some(exit) = self.rt.remove_exit(cache.bw_circuit_id) else {
                info!("Created for unknown exit socket {}", cache.bw_circuit_id);
                return Ok(());
            };

            let session_keys: Vec<SessionKeys> = (**exit.keys.load()).clone();
            let relay = Arc::new(Relay::new(
                cache.fw_circuit_id,
                cache.fw_addr,
                exit.circuit_id,
                exit.peer,
                self.rt.settings.load().max_relay_early,
            ));
            relay.keys.store(Arc::new(session_keys));

            self.rt.insert_relay(cache.fw_circuit_id, relay.clone());
            self.rt.insert_relay(cache.bw_circuit_id, relay.clone());

            let extended = ExtendedPayload {
                circuit_id: relay.circuit_id_bw,
                identifier: cache.identifier,
                key: VarLenH { data_len: payload.key.data_len, data: payload.key.data },
                auth: payload.auth,
                candidates_enc: Raw { data: payload.candidates_enc.data },
            };

            return self.rt.send_cell(&extended, None).await.map(|_| ());
        }

        let circuits = self.rt.circuits.load();
        let Some(circuit) = circuits.get(&circuit_id) else {
            warn!("Got unexpected created for circuit {}", payload.identifier);
            return Ok(());
        };

        if circuit.state() != CircuitState::Extending {
            info!("Circuit not extending, dropping created");
            return Ok(());
        }

        info!("Got created for circuit {} with id {}", circuit_id, payload.identifier);
        if let Err(e) = self
            .ours_on_created_extended(
                &circuit,
                &payload.key.data,
                &payload.auth,
                &payload.candidates_enc.data,
            )
            .await
        {
            error!("Error processing created: {}", e);
        };
        Ok(())
    }

    pub async fn on_extend(&self, _address: SocketAddr, circuit_id: u32, cell: &mut Vec<u8>) -> Result<()> {
        let payload: ExtendPayload = unpack_cell_payload(cell)?;

        let settings = self.rt.settings.load();
        if !settings.peer_flags.contains(&PeerFlag::Relay) {
            warn!("Ignoring extend for circuit {}", circuit_id);
            return Ok(());
        }

        let exits = self.rt.exits.load();
        let Some(_) = exits.get(&circuit_id) else {
            warn!("Got unexpected extend for unknown exit: {circuit_id}");
            return Ok(());
        };

        let target = match self.peer_cache.get_by_public_key_bin(&payload.node_public_key.data) {
            Some(cached_node) => cached_node.peer.address,
            None => match payload.node_addr {
                Address::V4(addr) => SocketAddr::V4(addr),
                Address::V6(addr) => SocketAddr::V6(addr),
                Address::DomainAddress(_, _) => return Err("cannot extend to domain address".to_owned()),
            },
        };

        let node_public_key = self.rt.runtime.get_my_public_key();
        let to_circuit_id = self.generate_circuit_id();
        let identifier = self.request_cache.generate_identifier() as u16;

        let create = CreatePayload {
            circuit_id: to_circuit_id,
            identifier,
            node_public_key: VarLenH { data_len: node_public_key.len() as u16, data: node_public_key },
            key: VarLenH { data_len: payload.key.data_len as u16, data: payload.key.data },
        };

        let cache: CreateRequestCache = CreateRequestCache {
            identifier: payload.identifier,
            fw_circuit_id: to_circuit_id,
            fw_addr: target,
            bw_circuit_id: circuit_id,
        };
        self.request_cache.add_identifier(
            "CreateRequestCache".to_owned(),
            identifier,
            Some(settings.next_hop_timeout.into()),
            Some(Arc::new(cache)),
        );

        self.rt.send_cell(&create, Some(target)).await?;
        Ok(())
    }

    pub async fn on_extended(&self, _address: SocketAddr, circuit_id: u32, cell: &mut Vec<u8>) -> Result<()> {
        let payload: ExtendedPayload = unpack_cell_payload(cell)?;

        let circuits = self.rt.circuits.load();
        let Some(circuit) = circuits.get(&circuit_id) else {
            warn!("Got unexpected extended for circuit {}", payload.identifier);
            return Ok(());
        };

        if circuit.state() != CircuitState::Extending {
            info!("Circuit not extending, dropping extended");
            return Ok(());
        }

        info!("Got extended for circuit {} with id {}", circuit_id, payload.identifier);
        if let Err(e) = self
            .ours_on_created_extended(
                &circuit,
                &payload.key.data,
                &payload.auth,
                &payload.candidates_enc.data,
            )
            .await
        {
            error!("Error processing extended: {}", e);
        };
        Ok(())
    }

    pub async fn ours_on_created_extended(
        &self,
        circuit: &Arc<Circuit>,
        key_data: &[u8],
        auth: &[u8],
        candidates_enc_data: &[u8],
    ) -> Result<()> {
        let old_hops = circuit.hops.load();

        let Some(hop) = old_hops.unverified.clone() else {
            return Err("No unverified hop found".to_owned());
        };

        let Some(dh_secret) = &hop.dh_secret else {
            return Err("Missing DH secret".to_owned());
        };

        let Ok(crypt_pk) = hop.peer.public_key.get_crypt_pk() else {
            return Err("Missing DH crypt_pk".to_owned());
        };

        let session_keys = match SessionKeys::verify_outbound(dh_secret, &crypt_pk, key_data, auth) {
            Ok(keys) => keys,
            Err(e) => {
                error!("Crypto handshake for circuit {} failed: {}", circuit.circuit_id, e);
                circuit.closing.store(true, std::sync::atomic::Ordering::Relaxed);
                self.rt.remove_circuit(circuit.circuit_id);
                return Err(e.into());
            }
        };

        let hop_count = circuit.append_hop(session_keys.clone(), hop);
        info!("Added hop {} to circuit {}", hop_count, circuit.circuit_id);

        match circuit.state() {
            CircuitState::Extending => {
                if candidates_enc_data.len() > 2048 {
                    return Err("Candidates encrypted payload data block too large".to_owned());
                }

                let mut candidates_bin = Vec::with_capacity(candidates_enc_data.len());
                candidates_bin.extend_from_slice(candidates_enc_data);
                session_keys
                    .decrypt_in_place(&mut candidates_bin, Direction::Forward)
                    .map_err(|e| format!("Failed to decrypt candidates: {e}"))?;

                let (_, payload) = CandidatePayload::from_bytes((&candidates_bin, 0))
                    .map_err(|e| format!("error while decoding candidates: {e}").to_owned())?;

                let mut candidates = Vec::with_capacity(payload.keys.len());
                for key_entry in payload.keys {
                    if let Some(n) = self.peer_cache.get_by_public_key_bin(&key_entry.public_key_bin) {
                        candidates.push(n.peer.clone());
                    }
                }

                // Split list in relay/exit candidates
                let mut relay_candidates = candidates.clone();
                let mut exit_candidates = Vec::new();
                if candidates.len() > 1 {
                    for i in 0..(candidates.len() - 1) {
                        if candidates[i] == candidates[i + 1] {
                            relay_candidates = candidates[..i].to_vec();
                            exit_candidates = candidates[(i + 1)..].to_vec();
                            break;
                        }
                    }
                }

                let become_exit = (circuit.goal_hops as usize - 1) == hop_count;
                let chosen_list = if become_exit { &exit_candidates } else { &relay_candidates };
                let final_candidates =
                    if chosen_list.is_empty() { exit_candidates } else { relay_candidates };
                return self.send_extend(circuit, final_candidates).await;
            }
            CircuitState::Ready => {
                info!("Circuit {} has reached {} hops and is READY!", circuit.circuit_id, circuit.goal_hops);
                let _ = circuit.ready.set(Ok(()));
            }
            _ => warn!("Circuit {} encountered unhandled state: {:?}", circuit.circuit_id, circuit.state()),
        }

        Ok(())
    }

    pub async fn send_extend(&self, circuit: &std::sync::Arc<Circuit>, candidates: Vec<Peer>) -> Result<()> {
        let become_exit = (circuit.goal_hops as usize - 1) == circuit.hops.load().verified.len();

        let mut extend_hop_public_bin = Vec::new();
        let mut extend_hop_addr = SocketAddr::from(([0, 0, 0, 0], 0));

        if become_exit && circuit.required_exit.is_some() {
            if let Some(required_exit_peer) = &circuit.required_exit {
                extend_hop_public_bin = required_exit_peer.public_key.key_to_bin().unwrap_or_default();
                extend_hop_addr = required_exit_peer.address;
            }
        } else {
            let mut exclude = std::collections::HashSet::from([self.rt.runtime.get_my_public_key()]);
            exclude.extend(
                circuit.hops.load().verified.iter().filter_map(|hop| hop.peer.public_key.key_to_bin().ok()),
            );
            exclude.extend(circuit.required_exit.as_ref().and_then(|peer| peer.public_key.key_to_bin().ok()));

            if let Some(chosen_peer) = candidates
                .into_iter()
                .find(|p| p.public_key.key_to_bin().ok().map(|bin| !exclude.contains(&bin)).unwrap_or(false))
            {
                extend_hop_public_bin = chosen_peer.public_key.key_to_bin().unwrap_or_default();
                extend_hop_addr = chosen_peer.address;
            }

            // No eligible candidates found, so we pick one ourselves.
            if extend_hop_public_bin.is_empty() {
                let mut choices = self
                    .peer_cache
                    .peers(&std::collections::HashSet::from([PeerFlag::ExitBt, PeerFlag::Relay]));
                choices.retain(|p| !exclude.contains(&p.public_key.key_to_bin().unwrap_or_default()));

                if let Some(chosen_peer) = choices.choose(&mut rand::rng()) {
                    extend_hop_public_bin = chosen_peer.public_key.key_to_bin().unwrap_or_default();
                    extend_hop_addr = chosen_peer.address;
                    info!("No candidates to extend to, trying exit node {:?} instead", extend_hop_addr);
                }
            }
        }

        // Send extend to selected candidate
        if !extend_hop_public_bin.is_empty() {
            let public_key = PublicKey::from_bytes(&extend_hop_public_bin)
                .map_err(|e| format!("Invalid target public key: {e}"))?;

            let dh_secret = PrivateKey::generate("curve25519")?;
            let dh_first_part = dh_secret.get_crypt_pk()?;

            let mut hop =
                Hop::new(Peer { address: extend_hop_addr, public_key, private_key: None }, HashSet::new());
            hop.dh_secret = Some(dh_secret);

            circuit.hops.store(std::sync::Arc::new(Hops {
                verified: circuit.hops.load().verified.clone(),
                unverified: Some(hop),
            }));

            // TODO: set flags for hop
            info!("Extending circuit ID {} with {}", circuit.circuit_id, extend_hop_addr);

            let identifier = self.request_cache.generate_identifier() as u16;
            let extend = ExtendPayload {
                circuit_id: circuit.circuit_id,
                identifier,
                node_public_key: VarLenH {
                    data_len: extend_hop_public_bin.len() as u16,
                    data: extend_hop_public_bin,
                },
                key: VarLenH { data_len: dh_first_part.len() as u16, data: dh_first_part },
                node_addr: match extend_hop_addr {
                    SocketAddr::V4(a) => Address::V4(a),
                    SocketAddr::V6(a) => Address::V6(a),
                },
            };
            return self.rt.send_cell(&extend, None).await.map(|_| ());
        } else {
            warn!("Closing circuit {}, no candidates", circuit.circuit_id);
            circuit.closing.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    pub async fn on_ping(&self, address: SocketAddr, _circuit_id: u32, cell: &mut Vec<u8>) -> Result<()> {
        let request: PingPayload = unpack_cell_payload(cell)?;

        let cid = request.circuit_id;
        let cid_known = self.rt.circuits.load().contains_key(&cid)
            || self.rt.exits.load().contains_key(&cid)
            || self.rt.relays.load().contains_key(&cid);
        if !cid_known {
            return Ok(());
        }

        let res = PongPayload { circuit_id: cid, identifier: request.identifier };
        self.rt.send_cell(&res, None).await.map_err(|e| format!("Pong send error: {}", e))?;
        trace!("Ping from {}, sent pong for circuit {}", address, cid);
        Ok(())
    }

    pub async fn on_pong(&self, _address: SocketAddr, circuit_id: u32, cell: &mut Vec<u8>) -> Result<()> {
        let payload: PongPayload = unpack_cell_payload(cell)?;

        match self.request_cache.pop("PingRequestCache", payload.identifier) {
            CacheResult::Identifier(_) => {}
            _ => {
                warn!("Invalid ping identifier: {}", payload.identifier);
                return Ok(());
            }
        }

        info!("Got pong for circuit {}", circuit_id);
        Ok(())
    }

    pub async fn on_destroy(
        &self,
        _address: SocketAddr,
        circuit_id: u32,
        packet: &mut Vec<u8>,
    ) -> Result<()> {
        let (_, payload): (PublicKey, DestroyPayload) = unpack_signed_payload(packet)?;
        info!("Got destroy for circuit {} (reason={})", circuit_id, payload.reason);

        if let Some(circuit) = self.rt.circuits.load().get(&circuit_id) {
            self.rt.remove_circuit(circuit.circuit_id);
        } else if let Some(relay) = self.rt.relays.load().get(&circuit_id) {
            self.rt.remove_relay(relay.circuit_id_fw);
            self.rt.remove_relay(relay.circuit_id_bw);
        } else if let Some(exit) = self.rt.exits.load().get(&circuit_id) {
            self.rt.remove_exit(exit.circuit_id);
        }
        Ok(())
    }

    pub async fn on_test_request(
        &self,
        _address: SocketAddr,
        circuit_id: u32,
        cell: &mut Vec<u8>,
    ) -> Result<()> {
        debug!("Got test-request from circuit {}", circuit_id);
        let request: TestRequestPayload = unpack_cell_payload(cell)?;

        let mut random_data = vec![0; request.response_size.try_into().unwrap()];
        rand::rng().fill_bytes(&mut random_data);
        let response = TestResponsePayload {
            circuit_id,
            identifier: request.identifier,
            response: Raw { data: random_data },
        };

        match self.rt.send_cell(&response, None).await {
            Ok(_) => {
                debug!("Sending test-response over circuit {}", circuit_id);
                Ok(())
            }
            Err(e) => return Err(format!("error sending test-response: {}", e)),
        }
    }

    pub async fn on_test_response(
        &self,
        _address: SocketAddr,
        circuit_id: u32,
        cell: &mut Vec<u8>,
    ) -> Result<()> {
        debug!("Got test-response from circuit {}", circuit_id);
        let payload: TestResponsePayload = unpack_cell_payload(cell)?;
        if let Err(e) = self
            .rt
            .runtime
            .test_channel
            .try_send(TestMetric { identifier: payload.identifier, len: cell.len() as u16 })
        {
            warn!("Failed to send metrics over test_channel: {}", e);
        }
        Ok(())
    }

    pub async fn on_http_request(
        &self,
        _address: SocketAddr,
        circuit_id: u32,
        cell: &mut Vec<u8>,
    ) -> Result<()> {
        debug!("Got http-request from circuit {}", circuit_id);
        if !self.rt.settings.load().peer_flags.contains(&PeerFlag::ExitHttp) {
            return Err(format!("dropping http-request, exiting HTTP is disabled"));
        }
        let request: HTTPRequestPayload = unpack_cell_payload(cell)?;

        let permit_result = match self.rt.exits.load().get(&circuit_id) {
            Some(exit) => exit.http_requests.clone().try_acquire_owned(),
            None => return Err(format!("dropping http-request, unknown exit")),
        };
        let permit = match permit_result {
            Ok(permit) => permit,
            Err(_) => return Err(format!("dropping http-request, request limit reached")),
        };

        // Handling a HTTP request can take a while, so spawn a separate task.
        let rt = self.rt.clone();
        self.rt.task_manager.spawn("http_request", async move {
            let Ok(result) =
                timeout(Duration::new(5, 0), send_tcp_request(&request.target, &request.request.data)).await
            else {
                warn!("TCP stream timed out");
                return;
            };

            let (tcp_response, http_body) = match result {
                Ok(r) => r,
                Err(e) => {
                    warn!("TCP stream error: {}", e);
                    return;
                }
            };
            debug!("TCP response from {}: {}", request.target, String::from_utf8_lossy(&tcp_response));

            if !tcp_response.starts_with(b"HTTP/1.1 307") {
                if bdecode::bdecode(&http_body).is_err() {
                    warn!("HTTP response from {} is not bencoded", request.target);
                    return;
                };
                info!("HTTP response from {}", request.target);
            }

            let num_cells = u16::div_ceil(tcp_response.len() as u16, 1400);
            for (index, chunk) in tcp_response.to_vec().chunks(1400).enumerate() {
                let response = HTTPResponsePayload {
                    circuit_id,
                    identifier: request.identifier,
                    part: index as u16,
                    total: num_cells,
                    response: VarLenH { data_len: chunk.len() as u16, data: chunk.to_vec() },
                };

                match rt.send_cell(&response, None).await {
                    Ok(_) => debug!("Sending http-response ({}) over circuit {}", index + 1, circuit_id),
                    Err(e) => {
                        error!("Error sending http-response: {}", e);
                        return;
                    }
                };
            }
            // Ensure the permit gets moved into this task and dropped at the end.
            drop(permit);
        });
        Ok(())
    }

    pub async fn on_http_response(
        &self,
        _address: SocketAddr,
        circuit_id: u32,
        cell: &mut Vec<u8>,
    ) -> Result<()> {
        debug!("Got http-response from circuit {}", circuit_id);

        if cell.len() < 15 {
            return Err("Cell too small for HTTP response identifier".to_owned());
        }

        let identifier = u32::from_be_bytes(cell[30..34].try_into().unwrap());
        match self.request_cache.get("HTTPRequest", identifier) {
            CacheResult::Stream(cache) => {
                if let Err(_) = cache.send(cell.clone()).await {
                    return Err(format!("error handling http-response"));
                }
            }
            _ => return Err(format!("unexpected http-response")),
        }
        Ok(())
    }
}
