use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use _rust::community::serialization::{circuit_id_to_ip, Raw, Socks5Payload};
use _rust::peer::Peer;
use _rust::util::start_socks5_client;
use deku::DekuContainerWrite;
use tokio::net::UdpSocket;
use tracing::info;

use _rust::community::routing::circuit::{CircuitState, CircuitType};
use _rust::community::routing::peer::{PeerCache, PeerFlag};
use _rust::community::{Community, TunnelCommunity};
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
    let mut listeners = Vec::new();
    for i in 0..7 {
        let flags = match i {
            0..=1 => HashSet::from([]),
            2..=4 => HashSet::from([PeerFlag::Relay]),
            _ => HashSet::from([PeerFlag::Relay, PeerFlag::ExitIpv8, PeerFlag::ExitBt]),
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

    println!("Starting SOCKS5 server and DHT at seeder...");
    let seeder: &Arc<TunnelCommunity> = nodes.get(1).unwrap();
    let seeder_port = seeder.start_socks5_server(0, 2).await.expect("Failed to start seeder SOCKS5 server");
    let seeder_addr: SocketAddr = format!("127.0.0.1:{}", seeder_port).parse().unwrap();

    println!("Starting SOCKS5 server and DHT at downloader...");
    let downloader = nodes.get(0).unwrap();
    let downloader_port =
        downloader.start_socks5_server(0, 1).await.expect("Failed to start downloader SOCKS5 server");
    let downloader_addr: SocketAddr = format!("127.0.0.1:{}", downloader_port).parse().unwrap();

    let _ = nodes.get(2).unwrap().start_socks5_server(0, 1).await.expect("Failed to start SOCKS5 server");
    let _ = nodes.get(3).unwrap().start_socks5_server(0, 1).await.expect("Failed to start SOCKS5 server");
    let _ = nodes.get(4).unwrap().start_socks5_server(0, 1).await.expect("Failed to start SOCKS5 server");
    let _ = nodes.get(5).unwrap().start_socks5_server(0, 1).await.expect("Failed to start SOCKS5 server");

    // Only use 1 DHT instance during the benchmark
    for node in &nodes {
        let dht_guard = node.hs_state.dht.load();
        if let Some(wrapper) = dht_guard.as_ref() {
            unsafe {
                let wrapper_mut_ptr = Arc::as_ptr(wrapper) as *mut _rust::dht::engine::DHTWrapper;
                (*wrapper_mut_ptr).dht_discover = Arc::clone(&(*wrapper_mut_ptr).dht_announce);
            }
        }
    }

    println!("Connecting DHTs...");
    for i in 0..nodes.len() {
        for j in 0..nodes.len() {
            if i != j {
                let node_i: &Arc<TunnelCommunity> = nodes.get(i).unwrap();
                let node_j = nodes.get(j).unwrap();

                let dht_guard_j = node_j.hs_state.dht.load();
                let dht_guard_i = node_i.hs_state.dht.load();

                if let (Some(wrapper_i), Some(wrapper_j)) = (dht_guard_i.as_ref(), dht_guard_j.as_ref()) {
                    let id = wrapper_i.dht_announce.node_id;
                    let port = wrapper_i.dht_announce.transport.local_addr().unwrap().port();
                    let addr =
                        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), port);
                    wrapper_j.dht_announce.nodes.update(id, addr);
                }
            }
        }
    }

    println!("Starting DHT loops...");
    for node in &nodes {
        if let Some(dht_wrapper) = node.hs_state.dht.load().as_ref() {
            let discover_engine = Arc::clone(&dht_wrapper.dht_discover);
            node.rt.task_manager.spawn("bench_dht_discover_reactor", async move {
                let _ = discover_engine.listen_loop().await;
            });

            let announce_engine = Arc::clone(&dht_wrapper.dht_announce);
            node.rt.task_manager.spawn("bench_dht_announce_reactor", async move {
                let _ = announce_engine.listen_loop().await;
            });
        }
    }

    let mut test_info_hash = [1u8; 20];
    rand::fill(&mut test_info_hash);

    println!("Joining swarm at seeder...");
    seeder.join_swarm(test_info_hash.clone(), 1, true).expect("Seeder failed to join swarm");

    let intro_node = nodes.get(5).unwrap();
    let intro_sk_guard = intro_node.rt.runtime.my_sk.load();
    let intro_sk = intro_sk_guard.as_ref().expect("No my_sk for introduction point");

    let c = intro_node.create_circuit(1, CircuitType::Data, None, None, None).await.unwrap();
    let _ = c.ready.result().await;
    let c = downloader.create_circuit(1, CircuitType::Data, None, None, None).await.unwrap();
    let _ = c.ready.result().await;

    println!("Start get_ips response loop...");
    intro_node.response_ip_lookup().expect("Failed to start get_ips loop");

    println!("Creating introduction point...");
    let intro_peer = Peer {
        address: intro_node.local_addr,
        public_key: intro_sk.public_key().unwrap(),
        private_key: None,
    };

    seeder
        .create_introduction_point(&test_info_hash, Some(intro_peer.clone()))
        .await
        .expect("Failed to create introduction point");
    tokio::time::sleep(Duration::from_millis(100)).await;

    println!("Joining swarm at downloader...");
    let native_callback =
        _rust::community::hiddenservices::E2ECallback::Rust(Arc::new(|infohash, _virtual_ip, _port| {
            println!("E2E circuit established for swarm {}!", _rust::util::to_hex(&infohash),);
            Ok(())
        }));
    downloader.hs_state.e2e_callback.store(Some(Arc::new(native_callback)));
    downloader.start_circuit_manager();
    downloader.join_swarm(test_info_hash.clone(), 1, false).expect("Downloader failed to join swarm");
    downloader.start_peer_discovery();

    let circuit_id_dl;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let circuits = downloader.rt.circuits.load();

        if let Some((&id, circuit)) =
            circuits.iter().find(|(_, c)| c.circuit_type == CircuitType::RPDownloader)
        {
            if circuit.state() == CircuitState::Ready && circuit.is_e2e() {
                circuit_id_dl = id;
                break;
            }
        }
        println!("Waiting for RPDownloader...");
    }

    let virtual_addr = SocketAddr::new(IpAddr::V4(circuit_id_to_ip(circuit_id_dl)), 1024);

    info!("Connecting outbound SOCKS5 clients on both ends...");
    let (client_associate, _client_stream) =
        start_socks5_client(downloader_addr, Some(virtual_addr)).await.unwrap();
    let (seeder_associate, _seeder_stream) =
        start_socks5_client(seeder_addr, Some(virtual_addr)).await.unwrap();

    let stats = Arc::new(Stats::new());
    let client_socket = Arc::new(client_associate);
    let seeder_socket = Arc::new(seeder_associate);

    let recv_stats = stats.clone();
    let recv_socket: Arc<UdpSocket> = seeder_socket.clone();
    let recv_task_id = seeder.rt.task_manager.spawn("socks5_seeder_recv", async move {
        let mut inbound_buf = [0u8; 2048];
        loop {
            if let Ok(bytes_read) = recv_socket.recv(&mut inbound_buf).await {
                if bytes_read > 0 && inbound_buf[0] == 42 {
                    recv_stats.socket_stats.add_down(bytes_read, 0);
                }
            }
        }
    });

    let send_stats = stats.clone();
    let send_socket = client_socket.clone();
    let send_task_id = downloader.rt.task_manager.spawn("socks5_client_send", async move {
        let mut data = vec![0u8; 10 + 1400];
        rand::fill(&mut data);
        data[0] = 42;
        data[1] = 0;

        let payload = Socks5Payload { rsv: 0, frag: 0, dst: virtual_addr.into(), data: Raw { data } };
        let packet = payload.to_bytes().unwrap();

        loop {
            if let Ok(bytes_written) = send_socket.send(&packet).await {
                send_stats.socket_stats.add_up(bytes_written);
            }
        }
    });

    println!("Running E2E hidden services benchmark for 10s...");
    let start_instant = Instant::now();
    tokio::time::sleep(Duration::from_secs(10)).await;

    downloader.rt.task_manager.cancel_task(send_task_id);
    seeder.rt.task_manager.cancel_task(recv_task_id);
    drop(_client_stream);
    drop(_seeder_stream);

    let elapsed = start_instant.elapsed().as_secs_f64();

    let bytes_up = listeners.get(1).unwrap().stats.socket_stats.bytes_down.load(Ordering::Relaxed);
    let bytes_down = stats.socket_stats.bytes_up.load(Ordering::Relaxed);

    println!("\n┌─────────────────────────────────────────────────────────┐");
    println!("│             HIDDEN SERVICES BENCHMARK RESULTS           │");
    println!("└─────────────────────────────────────────────────────────┘");
    println!(" Elapsed time:                {:.2} seconds", elapsed);
    println!(" Total data cross-relayed:    {:.2} MB", to_mb(bytes_down));
    println!(" Speed out (Client):          {:.2} MB/s", to_mb(bytes_up) / elapsed);
    println!(" Speed in  (Seeder):          {:.2} MB/s", to_mb(bytes_down) / elapsed);
    println!(" ─────────────────────────────────────────────────────────");
    println!(" Host CPU threads available:  {}", settings.load().num_threads);
    println!(" Allocated workers:           {}", settings.load().worker_tasks);
    println!("└─────────────────────────────────────────────────────────┘\n");
}
