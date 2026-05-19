use std::net::SocketAddr;
use std::sync::Arc;

use crate::transport::buffer::Buffer;
use crate::util::Result;

pub mod engine;
pub mod handlers;
pub mod hiddenservices;
pub mod routing;
pub mod runtime;
pub mod serialization;
pub mod settings;
pub mod socks5;
pub mod speedtest;
pub mod tasks;
pub mod tunnels;

pub use tunnels::TunnelCommunity;

#[derive(Clone)]
pub enum Community {
    Tunnel(Arc<TunnelCommunity>),
}

impl Community {
    pub fn name(&self) -> &str {
        match self {
            Community::Tunnel(_) => "TunnelCommunity",
        }
    }

    #[inline(always)]
    pub fn to_python(&self, buf: &[u8]) -> bool {
        match self {
            Community::Tunnel(_) => {
                if buf.len() <= 22 {
                    return true;
                }

                // Message IDs that we don't recognize go to Python.
                match crate::community::serialization::MessageId::try_from(buf[22]) {
                    Ok(_) => false,
                    Err(_) => true,
                }
            }
        }
    }

    pub async fn on_packet(&self, src_addr: SocketAddr, packet: Buffer) -> Result<()> {
        match self {
            Community::Tunnel(c) => c.on_packet(src_addr, packet).await,
        }
    }
}
