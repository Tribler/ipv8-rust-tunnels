use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::{ArcSwap, ArcSwapOption};
use deku::{DekuContainerRead, DekuContainerWrite};
use tokio::net::{TcpStream, UdpSocket};

use crate::community::serialization::{Address, Raw, Socks5Payload};

pub enum TransportSocket {
    Direct(Arc<DirectUdpSocket>),
    Proxied(Arc<Socks5ProxiedSocket>),
}

impl TransportSocket {
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        match self {
            TransportSocket::Direct(s) => s.send_to(buf, target).await,
            TransportSocket::Proxied(s) => s.send_to(buf, target).await,
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        match self {
            TransportSocket::Direct(s) => s.recv_from(buf).await,
            TransportSocket::Proxied(s) => s.recv_from(buf).await,
        }
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match self {
            TransportSocket::Direct(s) => s.local_addr(),
            TransportSocket::Proxied(s) => s.local_addr(),
        }
    }
}

pub struct DirectUdpSocket {
    pub socket: UdpSocket,
}

impl DirectUdpSocket {
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        self.socket.send_to(buf, target).await
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

pub struct Socks5ProxiedSocket {
    pub proxy_addr: ArcSwap<SocketAddr>,
    pub udp: ArcSwapOption<UdpSocket>,
    pub stream: ArcSwapOption<TcpStream>,
}

impl Socks5ProxiedSocket {
    pub async fn new(proxy_addr: SocketAddr) -> Result<Arc<Self>, String> {
        let socket = Arc::new(Self {
            proxy_addr: ArcSwap::from_pointee(proxy_addr),
            udp: ArcSwapOption::from(None),
            stream: ArcSwapOption::from(None),
        });

        socket.reconnect().await?;
        Ok(socket)
    }

    pub async fn reconnect(self: &Arc<Self>) -> Result<(), String> {
        let proxy_addr = **(self.proxy_addr.load());

        warn!("Anonymous DHT reconnecting to proxy {}...", proxy_addr);
        let (proxy_udp, proxy_tcp) = crate::util::start_socks5_client(proxy_addr, None)
            .await
            .map_err(|e| format!("Failed to SOCKS5 associate: {}", e))?;

        self.udp.store(Some(Arc::new(proxy_udp)));
        self.stream.store(Some(Arc::new(proxy_tcp)));

        info!("Refreshed anonymous DHT associate socket");
        Ok(())
    }

    pub async fn send_to(self: &Arc<Self>, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        let guard = self.udp.load();
        let Some(udp_socket) = guard.as_ref() else {
            return Err(std::io::Error::other("error getting DHT socket"));
        };

        let payload = Socks5Payload { rsv: 0, frag: 0, dst: target.into(), data: Raw { data: buf.to_vec() } };
        let packet = payload
            .to_bytes()
            .map_err(|e| std::io::Error::other(format!("error serializing SOCKS5: {e}")))?;

        if let Err(e) = udp_socket.send(&packet).await {
            warn!("Failed to send DHT packet. Reconnecting now...");
            let self_clone = Arc::clone(self);
            tokio::spawn(async move {
                if let Err(err) = self_clone.reconnect().await {
                    error!("DHT reconnect failed: {}", err);
                }
            });

            return Err(e);
        }
        Ok(buf.len())
    }

    pub async fn recv_from(self: &Arc<Self>, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let guard = self.udp.load();
        let Some(udp_socket) = guard.as_ref() else {
            return Err(std::io::Error::other("error getting DHT socket"));
        };

        let mut inbound_buf = [0u8; 2048];
        let bytes_read = udp_socket.recv(&mut inbound_buf).await?;

        let (_, payload) = Socks5Payload::from_bytes((&inbound_buf[..bytes_read], 0))
            .map_err(|e| std::io::Error::other(format!("error unserializing SOCKS5: {e}")))?;

        let packet = payload.data.data;
        let origin: SocketAddr = match &payload.dst {
            Address::V4(addr) => SocketAddr::V4(*addr),
            Address::V6(addr) => SocketAddr::V6(*addr),
            Address::DomainAddress(var_len, port) => {
                let host_str = String::from_utf8_lossy(&var_len.data).into_owned();
                tokio::net::lookup_host(format!("{}:{}", host_str, port))
                    .await?
                    .next()
                    .ok_or_else(|| std::io::Error::other("failed to lookup host: empty address"))?
            }
        };

        let data_len = packet.len();
        buf[..data_len].copy_from_slice(&packet);
        Ok((data_len, origin))
    }

    pub fn local_addr(self: &Arc<Self>) -> std::io::Result<SocketAddr> {
        let guard = self.udp.load();
        let Some(udp_socket) = guard.as_ref() else {
            return Err(std::io::Error::other("error getting DHT socket"));
        };
        udp_socket.local_addr()
    }
}
