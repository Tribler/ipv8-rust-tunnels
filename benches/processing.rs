use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use rand::Rng;
use tracing::error;

use _rust::community::routing::circuit::CircuitType;
use _rust::community::routing::peer::{PeerCache, PeerFlag};
use _rust::community::serialization::{Raw, TestRequestPayload};
use _rust::community::tunnels::TunnelCommunity;
use _rust::task_manager::TaskManager;
use _rust::transport::settings::EndpointSettings;
use _rust::transport::stats::Stats;

use crate::common::{connect_communities, to_mb};

#[path = "../tests/common.rs"]
mod common;
use common::create_community;

fn build_network(num_nodes: u8) -> Vec<Arc<TunnelCommunity>> {
    let network = Arc::new(DashMap::new());
    let mut nodes: Vec<Arc<TunnelCommunity>> = Vec::new();

    for i in 0..num_nodes {
        let flags = match i {
            0 => HashSet::new(),
            _ if i == num_nodes - 1 => HashSet::from([PeerFlag::Relay, PeerFlag::ExitIpv8, PeerFlag::ExitBt]),
            _ => HashSet::from([PeerFlag::Relay]),
        };
        let addr: SocketAddr = format!("127.0.0.1:{}", i as u32 + 1000).parse().unwrap();
        let handle = tokio::runtime::Handle::try_current().unwrap();
        let tm = TaskManager::new(handle);
        let (community, rx_outbound) = create_community(addr, flags, PeerCache::new(), tm);
        network.insert(addr, community.clone());
        nodes.push(community.clone());

        let num_bridge_workers = 32;
        for _ in 0..num_bridge_workers {
            let rx_outbound_worker = rx_outbound.clone();
            let network_worker_clone = network.clone();
            let addr_worker_clone = addr.clone();

            tokio::spawn(async move {
                while let Ok((target_addr, buf)) = rx_outbound_worker.recv_async().await {
                    if let Some(c) = network_worker_clone.get(&target_addr) {
                        if let Err(e) = c.value().on_packet(addr_worker_clone, buf).await {
                            error!(
                                "Error while sending message from {} to {}: {}",
                                addr_worker_clone, target_addr, e
                            );
                        };
                    }
                }
            });
        }
    }
    connect_communities(&nodes);
    nodes
}

#[tokio::main]
async fn main() {
    _rust::telemetry::init_telemetry();

    let nodes = build_network(3);
    let origin = nodes.get(0).unwrap();

    let circuit = origin
        .create_circuit(2, CircuitType::Data, Some(HashSet::from([PeerFlag::ExitIpv8])), None, None)
        .await
        .expect("Failed to create circuit");
    let _ = circuit.ready.result().await;

    let stats = Arc::new(Stats::new());
    let tm = origin.rt.task_manager.clone();
    let settings = EndpointSettings::default();

    let mut recv_tasks = Vec::new();
    for i in 0..4 {
        let recv_rt = origin.rt.clone();
        let recv_stats = stats.clone();

        recv_tasks.push(tm.spawn(&format!("speedtest_rev_{}", i), async move {
            let receiver = &recv_rt.runtime.test_receiver;
            while let Ok(metric) = receiver.recv_async().await {
                recv_stats.socket_stats.add_down(metric.len as usize, 0);
            }
        }));
    }

    let circuit_id = circuit.circuit_id;
    let mut send_tasks = Vec::new();
    for i in 0..8 {
        let sender_rt = origin.rt.clone();
        let sender_stats = stats.clone();

        send_tasks.push(tm.spawn(&format!("speedtest_send_{}", i), async move {
            let mut random_data = [0; 2048];
            rand::rng().fill_bytes(&mut random_data);

            let mut test_request = TestRequestPayload {
                circuit_id,
                identifier: 0,
                response_size: 1400,
                request: Raw { data: random_data[..25 as usize].to_vec() },
            };

            loop {
                test_request.identifier = rand::random();
                if let Ok(n) = sender_rt.send_cell(&test_request, None).await {
                    sender_stats.socket_stats.add_up(n);
                }
                tokio::task::yield_now().await;
            }
        }));
    }

    println!("Running processing benchmark...");
    let start_instant = Instant::now();
    tokio::time::sleep(Duration::from_secs(10)).await;
    send_tasks.into_iter().for_each(|id| {
        tm.cancel_task(id);
    });
    let elapsed = start_instant.elapsed().as_secs_f64();
    tokio::time::sleep(Duration::from_millis(500)).await;
    recv_tasks.into_iter().for_each(|id| {
        tm.cancel_task(id);
    });
    tokio::time::sleep(Duration::from_millis(250)).await;

    let bytes_up = stats.socket_stats.bytes_up.load(Ordering::Relaxed);
    let bytes_down = stats.socket_stats.bytes_down.load(Ordering::Relaxed);

    println!("\n┌─────────────────────────────────────────────────────────┐");
    println!("│               PROCESSING BENCHMARK RESULTS              │");
    println!("└─────────────────────────────────────────────────────────┘");
    println!(" Elapsed time:                {:.2} seconds", elapsed);
    println!(" Total data received:         {:.2} MB", to_mb(bytes_down));
    println!(" Speed out:                   {:.2} MB/s", to_mb(bytes_up) / elapsed);
    println!(" Speed in:                    {:.2} MB/s", to_mb(bytes_down) / elapsed);
    println!(" ─────────────────────────────────────────────────────────");
    println!(" Host CPU threads available:  {}", settings.num_threads);
    println!(" Is single-threaded runtime:  {}", settings.single_threaded);
    println!("└─────────────────────────────────────────────────────────┘\n");
}
