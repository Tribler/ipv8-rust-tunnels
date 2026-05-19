use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::community::routing::rendezvous::Rendezvous;
use crate::community::routing::{circuit::Circuit, exit::ExitSocket, relay::Relay};
use crate::community::runtime::RuntimeContext;
use crate::community::serialization::{CellPayload, NO_CRYPTO_PACKETS};
use crate::community::settings::TunnelSettings;
use crate::crypto::keys::PrivateKey;
use crate::task_manager::TaskManager;
use crate::transport::buffer::{Buffer, BufferPool};
use crate::util::Result;

pub enum RoutingTarget {
    Circuit(Arc<Circuit>),
    Exit(Arc<ExitSocket>),
    Relay(Arc<Relay>),
    Rendezvous(Arc<Rendezvous>),
}

#[derive(Clone)]
pub struct RoutingTable {
    pub tx_outbound: flume::Sender<(SocketAddr, Buffer)>,
    pub circuits: Arc<ArcSwap<HashMap<u32, Arc<Circuit>>>>,
    pub relays: Arc<ArcSwap<HashMap<u32, Arc<Relay>>>>,
    pub rendezvous: Arc<ArcSwap<HashMap<u32, Arc<Rendezvous>>>>,
    pub exits: Arc<ArcSwap<HashMap<u32, Arc<ExitSocket>>>>,
    pub task_manager: TaskManager,
    pub outbound_pool: BufferPool,

    pub settings: Arc<ArcSwap<TunnelSettings>>,
    pub runtime: Arc<RuntimeContext>,
}

impl RoutingTable {
    pub fn new(
        tx_outbound: flume::Sender<(SocketAddr, Buffer)>,
        my_private_key: PrivateKey,
        settings: Arc<ArcSwap<TunnelSettings>>,
        task_manager: TaskManager,
    ) -> Self {
        let runtime = RuntimeContext::new();
        runtime.my_sk.store(Some(Arc::new(my_private_key)));

        Self {
            tx_outbound,
            circuits: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            relays: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            rendezvous: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            exits: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            task_manager,
            outbound_pool: BufferPool::new(2048, 2048),
            settings,
            runtime: Arc::new(runtime),
        }
    }

    pub fn get_routing_object(&self, id: u32) -> Option<RoutingTarget> {
        if let Some(circuit) = self.circuits.load().get(&id) {
            return Some(RoutingTarget::Circuit(circuit.clone()));
        }
        if let Some(exit) = self.exits.load().get(&id) {
            return Some(RoutingTarget::Exit(exit.clone()));
        }
        if let Some(relay) = self.relays.load().get(&id) {
            return Some(RoutingTarget::Relay(relay.clone()));
        }
        if let Some(rv_route) = self.rendezvous.load().get(&id) {
            return Some(RoutingTarget::Rendezvous(rv_route.clone()));
        }
        None
    }

    pub async fn send_cell(
        &self,
        payload: &impl deku::DekuContainerWrite,
        target_addr: Option<SocketAddr>,
    ) -> Result<usize> {
        // Note that this function assumes that the serialized payload will have circuit ID at position 1..5.
        let mut buffer = self.outbound_pool.pull().await.map_err(|e| format!("Outbound pool error: {e}"))?;
        let buf = buffer.inner.as_mut().unwrap();

        let bytes_written = payload.to_slice(&mut buf[..]).unwrap();
        buf.truncate(bytes_written);

        let mut cell = CellPayload::from_payload(buf, false, false).map_err(|e| e.to_string())?;

        let cell_id_byte = cell.cell_id();
        let circuit_id = cell.circuit_id();
        let crypto_needed = !NO_CRYPTO_PACKETS.contains(&cell_id_byte);
        let target_object = self.get_routing_object(circuit_id);
        let relay_early_flag = match &target_object {
            Some(RoutingTarget::Circuit(c)) => c.relay_early_left.load(Ordering::Relaxed) > 0,
            _ => false,
        };

        cell.set_plaintext(!crypto_needed);
        cell.set_relay_early(relay_early_flag);

        if crypto_needed {
            if let Some(target) = &target_object {
                match target {
                    RoutingTarget::Circuit(c) => c.add_all_layers(&mut cell)?,
                    RoutingTarget::Exit(e) => e.add_layer(&mut cell)?,
                    RoutingTarget::Relay(r) => r.apply_layer(&mut cell, false, circuit_id)?,
                    RoutingTarget::Rendezvous(rv) => rv.apply_layer(&mut cell, false, circuit_id)?,
                }
            }
        }

        let final_target_addr = match target_addr {
            Some(addr) => addr,
            None => match &target_object {
                Some(target) => match target {
                    RoutingTarget::Circuit(c) => c.process(&mut cell, false)?.unwrap(),
                    RoutingTarget::Exit(e) => e.process(&mut cell, false)?.unwrap(),
                    RoutingTarget::Relay(r) => r.process(&mut cell, false, circuit_id)?.unwrap(),
                    RoutingTarget::Rendezvous(rv) => rv.process(&mut cell, false, circuit_id)?.unwrap(),
                },
                None => return Err(format!("Unknown routing target for circuit ID {circuit_id}")),
            },
        };

        self.send_packet(final_target_addr, buffer).await
    }

    pub async fn send_packet(&self, target: SocketAddr, mut buffer: Buffer) -> Result<usize> {
        let buf = buffer.inner.as_mut().unwrap();
        let settings = self.settings.load();

        let payload_len = buf.len();

        buf.resize(payload_len + 22, 0);
        buf.copy_within(0..payload_len, 22);

        buf[0..22].copy_from_slice(&settings.prefix);

        if let Err(e) = self.tx_outbound.send_async((target, buffer)).await {
            return Err(format!("Outbound channel error: {}", e));
        }
        Ok(payload_len + 22)
    }

    pub fn insert_circuit(&self, circuit_id: u32, circuit: Arc<Circuit>) {
        self.circuits.rcu(|active_map| {
            let mut new_map = (**active_map).clone();
            new_map.insert(circuit_id, Arc::clone(&circuit));
            new_map
        });
    }

    pub fn remove_circuit(&self, circuit_id: u32) -> Option<Arc<Circuit>> {
        let mut item = None;
        self.circuits.rcu(|active_map| {
            let mut new_map = (**active_map).clone();
            item = new_map.remove(&circuit_id);
            new_map
        });
        item
    }

    pub fn insert_relay(&self, relay_id: u32, relay: Arc<Relay>) {
        self.relays.rcu(|active_map| {
            let mut new_map = (**active_map).clone();
            new_map.insert(relay_id, Arc::clone(&relay));
            new_map
        });
    }

    pub fn remove_relay(&self, relay_id: u32) -> Option<Arc<Relay>> {
        let mut item = None;
        self.relays.rcu(|active_map| {
            let mut new_map = (**active_map).clone();
            item = new_map.remove(&relay_id);
            new_map
        });
        item
    }

    pub fn insert_exit(&self, circuit_id: u32, exit: Arc<ExitSocket>) {
        self.exits.rcu(|active_map| {
            let mut new_map = (**active_map).clone();
            new_map.insert(circuit_id, Arc::clone(&exit));
            new_map
        });
    }

    pub fn remove_exit(&self, circuit_id: u32) -> Option<Arc<ExitSocket>> {
        let mut item = None;
        self.exits.rcu(|active_map| {
            let mut new_map = (**active_map).clone();
            item = new_map.remove(&circuit_id);
            new_map
        });
        item
    }
}
