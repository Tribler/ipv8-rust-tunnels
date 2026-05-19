#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use _rust::community::hiddenservices::HiddenServiceState;
use _rust::peer::Peer;
use arc_swap::ArcSwapAny;
use flume::{self, Receiver};
use tracing::{error, info};

use _rust::community::routing::peer::{PeerCache, PeerFlag};
use _rust::community::routing::table::RoutingTable;
use _rust::community::settings::TunnelSettings;
use _rust::community::socks5::Socks5Server;
use _rust::community::tunnels::TunnelCommunity;
use _rust::crypto::keys::PrivateKey;
use _rust::task_manager::TaskManager;
use _rust::transport::buffer::{Buffer, BufferPool};
use _rust::transport::listener::PacketListener;
use _rust::transport::router::PacketRouter;
use _rust::transport::settings::EndpointSettings;
use _rust::transport::stats::Stats;
use _rust::transport::worker::WorkerPool;

pub fn to_mb(num_bytes: u64) -> f64 {
    (num_bytes as f64) / (1024.0 * 1024.0)
}

pub fn create_listener(
    addr: SocketAddr,
    settings: Arc<ArcSwapAny<Arc<EndpointSettings>>>,
    manager: &TaskManager,
) -> Arc<PacketListener> {
    let stats = Arc::new(Stats::new());
    let pool = BufferPool::new(1024, 2048);
    let socket = _rust::util::create_socket_with_retry(addr).unwrap();
    let worker_pool = WorkerPool::start(&manager, EndpointSettings::default().worker_tasks, None);
    let router = Arc::new(PacketRouter::new(
        std::collections::HashMap::new(),
        settings,
        worker_pool.tx_rust(),
        worker_pool.tx_python(),
    ));
    Arc::new(PacketListener::new(socket, router, stats, pool))
}

pub fn create_listener_tasks(
    listener: Arc<PacketListener>,
    manager: &TaskManager,
    rx_outbound: Receiver<(SocketAddr, Buffer)>,
) {
    let settings = EndpointSettings::default();
    for i in 0..settings.recv_tasks {
        let listener_clone = listener.clone();
        manager.spawn(&format!("udp-listen-loop-{}", i), async move {
            if let Err(e) = listener_clone.run_listen_loop(i).await {
                error!("Network listener loop {i} crashed: {:?}", e);
            }
        });
    }
    for i in 0..settings.send_tasks {
        let listener_clone = listener.clone();
        let rx_outbound_clone = rx_outbound.clone();
        manager.spawn(&format!("udp-send-loop-{}", i), async move {
            listener_clone.run_send_loop(i, rx_outbound_clone).await;
        });
    }
}

pub fn create_community(
    addr: SocketAddr,
    flags: HashSet<PeerFlag>,
    peer_cache: PeerCache,
    manager: TaskManager,
) -> (Arc<TunnelCommunity>, Receiver<(SocketAddr, Buffer)>) {
    let (tx_outbound, rx_outbound) = flume::bounded::<(SocketAddr, Buffer)>(4096);

    let mut prefix = [0x00; 22];
    prefix[1] = 0x02;

    let mut settings = TunnelSettings::new();
    settings.prefix = prefix.to_vec();
    settings.prefixes = vec![settings.prefix.clone()];
    settings.peer_flags = flags.clone();
    settings.exit_addr = "127.0.0.1:0".parse().unwrap();

    let my_sk = PrivateKey::generate("curve25519").unwrap();
    let routing_table = RoutingTable::new(
        tx_outbound,
        my_sk.clone(),
        Arc::new(arc_swap::ArcSwap::from_pointee(settings)),
        manager,
    );
    routing_table.runtime.my_estimated_wan.store(Some(Arc::new(addr)));

    let community: Arc<TunnelCommunity> = Arc::new(TunnelCommunity {
        prefix,
        rt: routing_table,
        peer_cache: peer_cache.clone(),
        request_cache: Default::default(),
        self_handle: Default::default(),
        socks_servers: Arc::new(arc_swap::ArcSwap::from_pointee(HashMap::new())),
        local_addr: addr,
        hs_state: Arc::new(HiddenServiceState::new(None)),
    });

    community.self_handle.set(Arc::clone(&community)).expect("Failed to set TunnelCommunity self_handle");

    (community, rx_outbound)
}

pub fn connect_communities(nodes: &Vec<Arc<TunnelCommunity>>) {
    for node in nodes {
        let sk_guard = node.rt.runtime.my_sk.load();
        let Some(my_sk) = sk_guard.as_ref() else {
            continue;
        };

        let peer_flags = node.rt.settings.load().peer_flags.clone();
        let peer_entry =
            Peer { address: node.local_addr, public_key: my_sk.public_key().unwrap(), private_key: None };

        for target in nodes {
            if target.local_addr != node.local_addr {
                target.peer_cache.add(peer_entry.clone(), peer_flags.clone());
            }
        }
    }
}

pub fn start_socks5_server(port: u16, hops: u8, tc: &Arc<TunnelCommunity>) -> u16 {
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    let community = tc.clone();
    tc.rt.task_manager.spawn("socks5_server", async move {
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to create Socks5 TCP listener: {}", e);
                return;
            }
        };
        let listen_addr = listener.local_addr().unwrap();
        info!("Socks5 server (hops={}) listening on: {:?}", hops, listen_addr);
        let mut server = Socks5Server::new(community.rt.clone(), community.request_cache.clone(), hops);
        community.socks_servers.rcu(|active_map| {
            let mut new_map = (**active_map).clone();
            new_map.insert(listen_addr, server.clone());
            new_map
        });
        addr_tx.send(listen_addr).expect("Failed to send Socks5 port");
        let _ = server.listen_forever(listener).await;
    });

    let bound_addr = addr_rx.recv().expect("Failed to start Socks5 server");
    bound_addr.port()
}
