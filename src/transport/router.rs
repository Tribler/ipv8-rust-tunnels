use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use flume;

use crate::community::Community;
use crate::transport::buffer::Buffer;
use crate::transport::settings::EndpointSettings;
use crate::transport::worker::{PythonWork, RustWork};
use crate::util::Result;

pub enum RoutingResult {
    Routed,
    Unmatched,
}

pub struct PacketRouter {
    pub communities: ArcSwap<HashMap<[u8; 22], Community>>,
    pub settings: Arc<ArcSwap<EndpointSettings>>,
    tx_rust: flume::Sender<RustWork>,
    tx_python: flume::Sender<PythonWork>,
}

impl PacketRouter {
    pub fn new(
        communities: HashMap<[u8; 22], Community>,
        settings: Arc<ArcSwap<EndpointSettings>>,
        tx_rust: flume::Sender<RustWork>,
        tx_python: flume::Sender<PythonWork>,
    ) -> Self {
        PacketRouter { communities: ArcSwap::from_pointee(communities), settings, tx_rust, tx_python }
    }

    pub async fn route_packet(&self, packet: Buffer, src_addr: SocketAddr) -> Result<RoutingResult> {
        // Peek at the inner bytes safely without moving ownership
        let buf_ref = packet.inner.as_ref().unwrap();
        if buf_ref.len() < 22 {
            return Ok(RoutingResult::Unmatched);
        }

        let mut prefix = [0u8; 22];
        prefix.copy_from_slice(&buf_ref[..22]);

        // Move packets to Rust workers
        if let Some(community) = self.communities.load().get(&prefix) {
            if community.to_python(buf_ref) {
                self.add_python_packet(buf_ref, src_addr);
            } else {
                self.add_rust_packet(community, packet, src_addr);
            }
            return Ok(RoutingResult::Routed);
        }

        // Move packets to Python workers
        let guard = self.settings.load();
        if guard.prefixes.iter().any(|p| buf_ref.starts_with(p)) {
            self.add_python_packet(buf_ref, src_addr);
            return Ok(RoutingResult::Routed);
        }

        Ok(RoutingResult::Unmatched)
    }

    pub fn add_rust_packet(&self, community: &Community, packet: Buffer, src_addr: SocketAddr) {
        let payload = RustWork { community: community.clone(), packet, src_addr };

        if let Err(flume::TrySendError::Full(_)) = self.tx_rust.try_send(payload) {
            warn!("Rust queue full!");
        } else if self.tx_rust.is_disconnected() {
            error!("Rust channel disconnected!");
        }
    }

    pub fn add_python_packet(&self, packet: &Vec<u8>, src_addr: SocketAddr) {
        let payload = PythonWork { packet: packet.to_vec(), src_addr };

        if let Err(flume::TrySendError::Full(_)) = self.tx_python.try_send(payload) {
            warn!("Python queue full!");
        } else if self.tx_python.is_disconnected() {
            error!("Python channel disconnected!");
        }
    }

    pub fn update_prefix(&self, old_prefix: &[u8; 22], new_prefix: [u8; 22]) {
        let mut new_communities = (**self.communities.load()).clone();

        let old_hex: String = old_prefix.iter().map(|b| format!("{:02X}", b)).collect();
        let new_hex: String = new_prefix.iter().map(|b| format!("{:02X}", b)).collect();

        if let Some(community) = new_communities.remove(old_prefix) {
            info!("Updating community prefix to: {:?}", new_hex);
            new_communities.insert(new_prefix, community);
            self.communities.swap(Arc::new(new_communities));
        } else {
            warn!("Prefix {:?} not found during update", old_hex);
        }
    }
}
