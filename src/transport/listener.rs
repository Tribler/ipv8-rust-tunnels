use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::transport::buffer::{Buffer, BufferPool};
use crate::transport::router::{PacketRouter, RoutingResult};
use crate::transport::stats::Stats;

pub struct PacketListener {
    pub socket: Arc<UdpSocket>,
    pub router: Arc<PacketRouter>,
    pub stats: Arc<Stats>,
    pub buffer_pool: BufferPool,
}

impl PacketListener {
    pub fn new(
        socket: Arc<UdpSocket>,
        router: Arc<PacketRouter>,
        stats: Arc<Stats>,
        buffer_pool: BufferPool,
    ) -> Self {
        PacketListener { socket, router, stats, buffer_pool }
    }

    pub async fn run_send_loop(
        self: Arc<Self>,
        worker_id: usize,
        rx_outbound: flume::Receiver<(SocketAddr, Buffer)>,
    ) {
        while let Ok((dest, work)) = rx_outbound.recv_async().await {
            let packet_bytes = work.inner.as_ref().unwrap();
            let packet_len = packet_bytes.len();

            self.stats.add_up(packet_bytes, packet_len);

            if let Err(e) = self.socket.send_to(packet_bytes, dest).await {
                if e.kind() != std::io::ErrorKind::ConnectionRefused {
                    error!("Worker {} socket error: {:?}", worker_id, e);
                }
            }
        }
    }

    pub async fn run_listen_loop(&self, worker_id: usize) -> Result<(), String> {
        loop {
            let mut buffer = self
                .buffer_pool
                .pull()
                .await
                .map_err(|e| format!("Worker {worker_id} buffer pull failed: {e}"))?;

            let mut raw_buf = buffer.inner.as_mut().unwrap();

            match self.socket.recv_from(&mut raw_buf).await {
                Ok((n, addr)) => {
                    if n == 0 {
                        continue;
                    }

                    self.stats.add_down(&raw_buf[..n], n);
                    raw_buf.truncate(n);

                    match self.router.route_packet(buffer, addr).await {
                        Ok(RoutingResult::Routed) => {}
                        Ok(RoutingResult::Unmatched) => {
                            trace!("Worker {} dropped unmatched packet", worker_id)
                        }
                        Err(e) => error!("Error while routing packet: {:?}", e),
                    }
                }
                Err(ref e) if e.raw_os_error() == Some(10040) => {
                    continue;
                }
                Err(e) => {
                    warn!("Worker {} intercepted socket error: {:?}", worker_id, e);
                    continue;
                }
            }
        }
    }

    pub async fn start_pool_monitor(&self, pool_total_size: usize) {
        let check_interval = std::time::Duration::from_secs(2);
        let pool_sender = self.buffer_pool.sender();

        loop {
            tokio::time::sleep(check_interval).await;

            let buffers_in_pool = pool_sender.len();

            debug!("Healthy: {} buffers waiting in the pool", buffers_in_pool);

            if buffers_in_pool == 0 {
                error!("CRITICAL ERROR: Pool has zero buffers remaining out of {}!", pool_total_size);
            } else if buffers_in_pool < (pool_total_size / 10) {
                warn!("Pool has {} / {} buffers remaining", buffers_in_pool, pool_total_size);
            }
        }
    }

    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.socket.local_addr().unwrap()
    }

    pub fn router(&self) -> &Arc<PacketRouter> {
        &self.router
    }

    pub fn stats(&self) -> Arc<Stats> {
        Arc::clone(&self.stats)
    }
}
