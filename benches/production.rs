use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use _rust::util::start_socks5_client;
use rand::Rng;
use socks5_proto::{Address as Socks5Address, UdpHeader};

use _rust::community::routing::circuit::CircuitType;
use _rust::community::routing::peer::{PeerCache, PeerFlag};
use _rust::community::Community;
use _rust::task_manager::TaskManager;
use _rust::transport::settings::EndpointSettings;
use _rust::transport::stats::Stats;

use crate::common::{connect_communities, to_mb};

#[path = "../tests/common.rs"]
mod common;
use common::{create_community, create_listener, create_listener_tasks, start_socks5_server};

async fn run_echo_server(socket: tokio::net::UdpSocket) {
    let mut buf = [0u8; 2048];

    loop {
        if let Ok((len, src_addr)) = socket.recv_from(&mut buf).await {
            if len > 0 {
                let _ = socket.send_to(&buf[..len], src_addr).await;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    _rust::telemetry::init_telemetry();

    let settings = Arc::new(arc_swap::ArcSwap::from_pointee(EndpointSettings::default()));
    let mut nodes = Vec::new();
    let mut listeners = Vec::new();
    let cache = PeerCache::new();
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

        create_listener_tasks(listener.clone(), &community.rt.task_manager, rx_outbound);
        nodes.push(community);
        listeners.push(listener);
    }

    connect_communities(&nodes);

    let origin = nodes.get(0).unwrap();
    let tm = origin.rt.task_manager.clone();

    let echo_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let echo_socket = tokio::net::UdpSocket::bind(echo_addr).await.unwrap();
    let echo_server_id = origin.rt.task_manager.spawn("echo_server", async move {
        run_echo_server(echo_socket).await;
    });

    let circuit = origin
        .create_circuit(2, CircuitType::Data, Some(HashSet::from([PeerFlag::ExitIpv8])), None, None)
        .await
        .expect("Failed to create circuit");
    let _ = circuit.ready.result().await;

    let server_port = start_socks5_server(0, 2, origin);
    let server_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
    let (associate, _stream) = start_socks5_client(server_addr, Some(echo_addr)).await.unwrap();

    let stats = Arc::new(Stats::new());
    let settings_guard = settings.load();
    let socket = Arc::new(associate);

    let recv_stats = stats.clone();
    let recv_socket = socket.clone();
    let recv_task_id = tm.spawn("socks5_client_recv", async move {
        let mut inbound_buf = [0u8; 2048];
        loop {
            if let Ok(bytes_read) = recv_socket.recv(&mut inbound_buf).await {
                recv_stats.socket_stats.add_down(bytes_read, 0);
            }
        }
    });

    let send_stats = stats.clone();
    let send_socket = socket.clone();
    let send_task_id = tm.spawn("socks5_client_send", async move {
        let mut payload = vec![1u8; 1400];
        rand::rng().fill_bytes(&mut payload);
        payload[0] = 65;
        payload[1] = 0;

        let udp_header = UdpHeader::new(0, Socks5Address::SocketAddress(server_addr));
        let mut packet = Vec::new();
        udp_header.write_to_buf(&mut packet);
        packet.extend_from_slice(&payload);

        loop {
            if let Ok(bytes_written) = send_socket.send(&packet).await {
                send_stats.socket_stats.add_up(bytes_written);
            }
        }
    });

    println!("Running production benchmark...");
    let start_instant = Instant::now();
    tokio::time::sleep(Duration::from_secs(10)).await;
    tm.cancel_task(send_task_id);
    tm.cancel_task(recv_task_id);
    drop(_stream);
    let elapsed = start_instant.elapsed().as_secs_f64();
    tokio::time::sleep(Duration::from_millis(250)).await;
    tm.cancel_task(echo_server_id);

    let bytes_up = listeners.get(2).unwrap().stats.socket_stats.bytes_down.load(Ordering::Relaxed);
    let bytes_down = stats.socket_stats.bytes_up.load(Ordering::Relaxed);

    println!("\n┌─────────────────────────────────────────────────────────┐");
    println!("│               PRODUCTION BENCHMARK RESULTS              │");
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
