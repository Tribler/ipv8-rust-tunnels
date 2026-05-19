use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bencode::{FromBencode, ToBencode};
use tokio::net::UdpSocket;

use crate::dht::serialization::{
    serialize_nodes_compact, unserialize_nodes_compact, unserialize_values_compact, AnnounceRequest,
    AnnounceResponse, BencodeMapExt, DhtMessage, DhtQuery, FindNodeRequest, FindNodeResponse,
    GetPeersRequest, GetPeersResponse, PingPayload,
};
use crate::dht::socket::{DirectUdpSocket, Socks5ProxiedSocket, TransportSocket};
use crate::dht::storage::{Node, Nodes, Values};
use crate::request_cache::{CacheResult, RequestCache};
use crate::task_manager::TaskManager;
use crate::util::{to_hex, Future};

pub struct LookupResult {
    pub nodes: Vec<Node>,
    pub values: Vec<SocketAddr>,
    pub auth: Option<(SocketAddr, Vec<u8>)>,
}

#[derive(Debug, Clone)]
pub struct ExtendedQuery {
    pub method: Vec<u8>,
    pub transaction_id: Vec<u8>,
    pub args: std::collections::BTreeMap<bencode::util::ByteString, bencode::Bencode>,
    pub origin: SocketAddr,
}

pub struct DHT {
    pub transport: TransportSocket,
    pub node_id: [u8; 20],
    pub request_cache: RequestCache,
    pub nodes: Nodes,
    pub values: Values,
    pub announces: Mutex<HashMap<[u8; 20], usize>>,
    pub task_manager: TaskManager,
    pub extensions_rx: flume::Receiver<ExtendedQuery>,
    extensions_tx: flume::Sender<ExtendedQuery>,
}

impl DHT {
    pub fn new(
        transport: TransportSocket,
        task_manager: TaskManager,
        max_nodes: usize,
        max_values: usize,
    ) -> Self {
        let (extensions_tx, extensions_rx) = flume::unbounded::<ExtendedQuery>();
        let mut node_id = [0u8; 20];
        rand::fill(&mut node_id);

        Self {
            transport,
            node_id,
            request_cache: RequestCache::new(),
            nodes: Nodes::new(node_id, max_nodes),
            values: Values::new(45, max_values),
            announces: Mutex::new(HashMap::new()),
            task_manager,
            extensions_tx,
            extensions_rx,
        }
    }

    pub async fn bootstrap(self: &Arc<Self>) -> Result<(), String> {
        let routers = [
            "dht.aelitis.com:6881",
            "dht.libtorrent.org:6881",
            "dht.libtorrent.org:25401",
            "dht.transmissionbt.com:6881",
            "router.bitcomet.com:6881",
            "router.bittorrent.com:6881",
            "router.utorrent.com:6881",
        ];

        info!("Bootstrapping DHT...");

        let mut set = tokio::task::JoinSet::new();

        for router in routers {
            let engine = Arc::clone(self);
            set.spawn(async move {
                let mut addrs = tokio::net::lookup_host(router).await.ok()?;
                let target_addr = addrs.find(|addr| addr.is_ipv4())?;

                let res = engine
                    .send_query(FindNodeRequest { id: engine.node_id, target: engine.node_id }, target_addr)
                    .await
                    .ok()?;

                let discovered = unserialize_nodes_compact(&res.nodes);
                if discovered.is_empty() {
                    return None;
                }
                Some((discovered, router))
            });
        }

        while let Some(task_result) = set.join_next().await {
            if let Ok(Some((discovered, router))) = task_result {
                info!("Bootstrapping finished, got {} nodes from {}", discovered.len(), router);
                for node in discovered {
                    self.nodes.update(node.id, node.address);
                }
                return Ok(());
            }
        }
        Err("Bootstrapping failed".to_owned())
    }

    pub async fn send_query<M>(&self, payload: M, target: SocketAddr) -> Result<M::Response, String>
    where
        M: DhtMessage,
        <M::Response as FromBencode>::Err: std::fmt::Debug,
    {
        let tx_id_u32 = self.request_cache.generate_identifier() as u16;
        let tx_bytes = tx_id_u32.to_be_bytes().to_vec();

        let timeout = M::DEFAULT_TIMEOUT;
        let dht_future = Arc::new(Future::<DhtQuery>::new());
        self.request_cache.add_identifier(
            "dht".to_string(),
            tx_id_u32,
            Some(timeout.as_secs()),
            Some(dht_future.clone()),
        );

        let bencode::Bencode::Dict(query_dict) = payload.to_bencode() else {
            return Err("Failed to bencode request".to_owned());
        };

        let query =
            DhtQuery { t: tx_bytes, y: b"q".to_vec(), q: M::METHOD.to_vec(), a: Some(query_dict), r: None };

        let packet =
            query.to_bencode().to_bytes().map_err(|e| format!("Failed to serialize request: {:?}", e))?;
        self.transport.send_to(&packet, target).await?;

        let response = dht_future
            .result_timeout(timeout)
            .await
            .map_err(|e| format!("Failed to get response from {target}: {e}"))?;

        let response_map = response.r.as_ref().ok_or_else(|| "Failed to get 'r' from response".to_owned())?;
        let response_dict = bencode::Bencode::Dict(response_map.clone());
        M::Response::from_bencode(&response_dict).map_err(|e| format!("Failed to parse 'r': {:?}", e))
    }

    pub async fn send_response<R>(
        &self,
        payload: R,
        transaction_id: Vec<u8>,
        target: SocketAddr,
    ) -> Result<(), String>
    where
        R: bencode::ToBencode,
    {
        let bencode::Bencode::Dict(response_dict) = payload.to_bencode() else {
            return Err("Failed to bencode response".to_owned());
        };

        let response =
            DhtQuery { t: transaction_id, y: b"r".to_vec(), q: Vec::new(), a: None, r: Some(response_dict) };

        let packet =
            response.to_bencode().to_bytes().map_err(|e| format!("Failed to serialize response: {:?}", e))?;
        self.transport.send_to(&packet, target).await?;
        Ok(())
    }

    pub async fn listen_loop(&self) -> Result<(), String> {
        info!("Starting DHT listen loop...");
        let mut buffer = [0u8; 2048];

        loop {
            let (bytes_read, origin) = self.transport.recv_from(&mut buffer).await?;
            let pkt = &buffer[..bytes_read];

            let pkt_query = match DhtQuery::from_buffer(pkt) {
                Ok(pkt) => pkt,
                Err(e) => {
                    error!("Decoding error: {:?}", e);
                    continue;
                }
            };

            let Ok(tx_id_u16) = pkt_query.transaction_id() else {
                continue;
            };

            match pkt_query.y.as_slice() {
                b"r" => {
                    if let CacheResult::Identifier(Some(any_data)) = self.request_cache.pop("dht", tx_id_u16)
                    {
                        if let Some(dht_future) = any_data.downcast_ref::<Future<DhtQuery>>() {
                            let _ = dht_future.set(pkt_query);
                        }
                    }
                }
                b"q" => {
                    if let Err(e) = self.handle_request(pkt_query, origin).await {
                        error!("Error processing request from {origin}: {e}");
                    }
                }
                _ => {
                    debug!("Dropped unknown packet from {origin}");
                }
            }
        }
    }

    async fn handle_request(&self, frame: DhtQuery, origin: SocketAddr) -> Result<(), String> {
        let Some(ref args_map) = frame.a else {
            return Err("Request missing arguments.".to_owned());
        };
        let args_bencode = bencode::Bencode::Dict(args_map.clone());

        let remote_id = args_map.get_array::<20>("id")?;
        self.nodes.update(remote_id, origin);

        match frame.q.as_slice() {
            b"ping" => {
                let req = PingPayload::from_bencode(&args_bencode)?;
                debug!("Received Ping request from DHT peer node: {:?}", req.id);
                self.send_response(PingPayload { id: self.node_id }, frame.t, origin).await?;
            }
            b"get_peers" => {
                let req = GetPeersRequest::from_bencode(&args_bencode)?;
                debug!("Received GetPeers lookup for info-hash: {:?}", req.info_hash);

                let values = self.values.get_peers(&req.info_hash);
                let nodes = values.is_none().then(|| {
                    let closest = self.nodes.find_closest(req.info_hash, 8);
                    serialize_nodes_compact(closest)
                });

                let resp = GetPeersResponse { id: self.node_id, token: b"token".to_vec(), values, nodes };
                self.send_response(resp, frame.t, origin).await?;
            }
            b"find_node" => {
                let req = FindNodeRequest::from_bencode(&args_bencode)?;
                debug!("Received FindNode lookup request for target node: {:?}", req.target);
                self.nodes.update(req.id, origin);

                let closest_nodes = self.nodes.find_closest(req.target, 8);
                let serialized_nodes = crate::dht::serialization::serialize_nodes_compact(closest_nodes);

                let resp = FindNodeResponse { id: self.node_id, nodes: serialized_nodes };
                self.send_response(resp, frame.t, origin).await?;
            }
            b"announce_peer" => {
                let req = AnnounceRequest::from_bencode(&args_bencode)?;
                debug!("Received Announce request for swarm: {:?} on port: {}", req.info_hash, req.port);
                self.nodes.update(req.id, origin);

                let mut peer_addr = origin;
                if req.port != 0 {
                    peer_addr.set_port(req.port);
                }
                self.values.store_peer(req.info_hash, peer_addr);

                self.send_response(AnnounceResponse { id: self.node_id }, frame.t, origin).await?;
            }
            extension_name => {
                debug!("Received extension '{}'...", String::from_utf8_lossy(extension_name));
                let _ = self.extensions_tx.send(ExtendedQuery {
                    method: extension_name.to_vec(),
                    transaction_id: frame.t.clone(),
                    args: args_map.clone(),
                    origin,
                });
            }
        };

        Ok(())
    }

    pub async fn lookup(&self, info_hash: [u8; 20]) -> Result<LookupResult, String> {
        info!("Starting lookup for {}...", to_hex(info_hash));

        let mut final_result = LookupResult { nodes: Vec::new(), values: Vec::new(), auth: None };
        let mut done = std::collections::HashSet::new();
        let mut todo = self.nodes.find_closest(info_hash, 20);

        let mut closest = todo.clone();
        let mut counter = 0;

        while !todo.is_empty() {
            counter += 1;
            if counter >= 40 {
                info!("Maximum crawl iterations reached: {}", counter);
                break;
            }

            let target = todo.remove(0);
            if !done.insert(target.address) {
                continue;
            }

            let Ok(result) =
                self.send_query(GetPeersRequest { id: self.node_id, info_hash }, target.address).await
            else {
                continue;
            };

            if !result.token.is_empty() {
                final_result.auth = Some((target.address, result.token));
            }

            if let Some(compact_values) = result.values {
                if !compact_values.is_empty() {
                    final_result.values.extend(unserialize_values_compact(&compact_values));
                    info!("Got {} values (after {} iterations)", final_result.values.len(), counter);
                    break;
                }
            }

            if let Some(compact_nodes) = result.nodes {
                let discovered_nodes = unserialize_nodes_compact(&compact_nodes);
                for node in discovered_nodes {
                    self.nodes.update(node.id, node.address);

                    if !done.contains(&node.address) && !todo.iter().any(|n| n.address == node.address) {
                        todo.push(node.clone());
                    }

                    if !closest.iter().any(|n| n.address == node.address) {
                        closest.push(node);
                    }
                }
            }

            todo.sort_by_cached_key(|node| node.distance_to(&info_hash));
        }

        closest.sort_by_cached_key(|node| node.distance_to(&info_hash));
        closest.truncate(8);
        final_result.nodes = closest;

        Ok(final_result)
    }

    pub fn start_announce(self: &Arc<Self>, info_hash: [u8; 20], port: Option<u16>) {
        let mut lock = self.announces.lock().unwrap();
        if lock.contains_key(&info_hash) {
            return;
        }

        info!("Starting announce for {}...", to_hex(info_hash));
        let dht_clone = Arc::clone(self);
        let task_name = format!("dht_announce_{}", to_hex(info_hash));

        let task_id =
            self.task_manager.spawn_interval(&task_name, Duration::from_secs(20 * 60), true, move || {
                let dht = Arc::clone(&dht_clone);
                async move {
                    let Ok(result) = dht.lookup(info_hash).await else {
                        return;
                    };
                    let Some((target, token)) = result.auth else {
                        warn!("No token while announcing");
                        return;
                    };

                    let msg = AnnounceRequest {
                        id: dht.node_id,
                        info_hash: info_hash,
                        token: token,
                        port: port.unwrap_or(0),
                    };
                    if let Err(e) = dht.send_query(msg, target).await {
                        warn!("Failed to announce to node {}: {}", target, e);
                    } else {
                        info!("Successfully announced {}", target);
                    }
                }
            });
        lock.insert(info_hash, task_id);
    }

    pub fn stop_announce(&self, info_hash: &[u8; 20]) -> bool {
        let mut lock = self.announces.lock().unwrap();
        if let Some(task_id) = lock.remove(info_hash) {
            info!("Stopping DHT announce task: {}", task_id);
            return self.task_manager.cancel_task(task_id);
        }
        false
    }

    pub fn start(self: &Arc<Self>) {
        info!("Starting DHT...");
        let dht_clone = Arc::clone(self);
        let task_name = format!("dht_listen_loop_{}", self.transport.local_addr().unwrap());
        self.task_manager.spawn(&task_name, async move {
            if let Err(e) = dht_clone.listen_loop().await {
                error!("DHT listen loop crashed: {}", e);
            }
        });
    }

    pub async fn shutdown(&self) {
        info!("Shutting down DHT {}...", self.transport.local_addr().unwrap());
        // Note that we assume the DHT will have it's own TaskManager,
        // so we have to take care of shutting it down ourselves.
        let tm = self.task_manager.clone();
        tm.shutdown(0).await;
        self.announces.lock().unwrap().clear();
    }
}

pub struct DHTWrapper {
    pub dht_discover: Arc<DHT>,
    pub dht_announce: Arc<DHT>,
}

impl DHTWrapper {
    pub async fn new(proxy_addr: SocketAddr, task_manager: TaskManager) -> Result<Self, String> {
        let proxy_socket = Socks5ProxiedSocket::new(proxy_addr).await?;
        let proxy_transport = TransportSocket::Proxied(proxy_socket);
        let dht_discover = DHT::new(proxy_transport, task_manager.clone(), 4096, 4096);

        let direct_udp = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("DHTWrapper failed to create UDP socket: {}", e))?;
        let direct_socket = Arc::new(DirectUdpSocket { socket: direct_udp });
        let direct_transport = TransportSocket::Direct(direct_socket);
        let dht_announce = DHT::new(direct_transport, task_manager, 4096, 4096);

        Ok(Self { dht_discover: Arc::new(dht_discover), dht_announce: Arc::new(dht_announce) })
    }

    pub async fn lookup(&self, info_hash: [u8; 20]) -> Result<LookupResult, String> {
        self.dht_discover.lookup(info_hash).await
    }

    pub fn start_announce(&self, info_hash: [u8; 20], port: Option<u16>) {
        self.dht_announce.start_announce(info_hash, port);
    }

    pub fn stop_announce(&self, info_hash: &[u8; 20]) -> bool {
        self.dht_announce.stop_announce(info_hash);
        true
    }

    pub fn start(&self) {
        self.dht_discover.start();
        self.dht_announce.start();
    }

    pub async fn shutdown(&self) {
        self.dht_discover.shutdown().await;
        self.dht_announce.shutdown().await;
    }
}
