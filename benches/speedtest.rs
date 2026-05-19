use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::Rng;

use _rust::community::routing::circuit::CircuitType;
use _rust::community::routing::peer::{PeerCache, PeerFlag};
use _rust::community::serialization::{Raw, TestRequestPayload};
use _rust::community::Community;
use _rust::task_manager::TaskManager;
use _rust::transport::settings::EndpointSettings;
use _rust::transport::stats::Stats;

#[path = "../tests/common.rs"]
mod common;
use common::{create_community, create_listener, create_listener_tasks, to_mb};

use crate::common::connect_communities;

#[tokio::main]
async fn main() {
    _rust::telemetry::init_telemetry();

    let settings = Arc::new(arc_swap::ArcSwap::from_pointee(EndpointSettings::default()));
    let mut nodes = Vec::new();
    for i in 0..3 {
        let flags = match i {
            0 => HashSet::new(),
            1 => HashSet::from([PeerFlag::Relay, PeerFlag::ExitIpv8, PeerFlag::ExitBt]),
            _ => HashSet::from([PeerFlag::Relay]),
        };
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let handle = tokio::runtime::Handle::try_current().unwrap();
        let tm = TaskManager::new(handle);
        let listener = create_listener(bind_addr, settings.clone(), &tm);
        let (community, rx_outbound) = create_community(listener.local_addr(), flags, PeerCache::new(), tm);

        let mut communities = listener.router().communities.load_full().as_ref().clone();
        communities.insert(community.prefix, Community::Tunnel(community.clone()));
        listener.router().communities.store(Arc::new(communities));

        create_listener_tasks(listener, &community.rt.task_manager, rx_outbound);
        nodes.push(community);
    }

    connect_communities(&nodes);

    let origin = nodes.get(0).unwrap();
    let tm = origin.rt.task_manager.clone();

    let circuit = origin
        .create_circuit(2, CircuitType::Data, Some(HashSet::from([PeerFlag::ExitIpv8])), None, None)
        .await
        .expect("Failed to create circuit");
    let _ = circuit.ready.result().await;

    let stats = Arc::new(Stats::new());
    let settings_guard = settings.load();

    for i in 0..settings_guard.recv_tasks {
        let recv_rt = origin.rt.clone();
        let recv_stats = stats.clone();

        tm.spawn(&format!("speedtest_rev_{}", i), async move {
            let receiver = &recv_rt.runtime.test_receiver;
            while let Ok(metric) = receiver.recv_async().await {
                recv_stats.socket_stats.add_down(metric.len as usize, 0);
            }
        });
    }

    let circuit_id = circuit.circuit_id;
    let mut send_tasks = Vec::new();
    for i in 0..settings_guard.send_tasks {
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
            }
        }));
    }

    println!("Running speedtest benchmark...");
    let start_instant = Instant::now();
    tokio::time::sleep(Duration::from_secs(10)).await;
    send_tasks.into_iter().for_each(|id| {
        tm.cancel_task(id);
    });
    let elapsed = start_instant.elapsed().as_secs_f64();
    tokio::time::sleep(Duration::from_millis(250)).await;

    let bytes_up = stats.socket_stats.bytes_up.load(Ordering::Relaxed);
    let bytes_down = stats.socket_stats.bytes_down.load(Ordering::Relaxed);

    println!("\n┌─────────────────────────────────────────────────────────┐");
    println!("│               SPEEDTEST BENCHMARK RESULTS               │");
    println!("└─────────────────────────────────────────────────────────┘");
    println!(" Elapsed time:                {:.2} seconds", elapsed);
    println!(" Total data received:         {:.2} MB", to_mb(bytes_down));
    println!(" Speed out:                   {:.2} MB/s", to_mb(bytes_up) / elapsed);
    println!(" Speed in:                    {:.2} MB/s", to_mb(bytes_down) / elapsed);
    println!(" ─────────────────────────────────────────────────────────");
    println!(" Host CPU threads available:  {}", settings_guard.num_threads);
    println!(" Is single-threaded runtime:  {}", settings_guard.single_threaded);
    println!(" Allocated workers:           {}", settings_guard.worker_tasks);
    println!("└─────────────────────────────────────────────────────────┘\n");
}
