use std::{
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use tokio::net::UdpSocket;

pub type Result<T> = std::result::Result<T, String>;

pub fn get_time() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(time) => time.as_secs(),
        Err(error) => {
            error!("Failed to get system time: {}", error);
            0
        }
    }
}

pub fn get_time_ms() -> u128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(time) => time.as_millis(),
        Err(error) => {
            error!("Failed to get system time: {}", error);
            0
        }
    }
}

pub fn create_socket(addr: SocketAddr) -> Result<Arc<UdpSocket>> {
    let socket_std = match std::net::UdpSocket::bind(addr) {
        Ok(socket) => {
            socket.set_nonblocking(true).unwrap();
            socket
        }
        Err(e) => return Err(e.to_string()),
    };
    let socket_tokio = match UdpSocket::from_std(socket_std) {
        Ok(socket) => socket,
        Err(e) => return Err(e.to_string()),
    };
    Ok(Arc::new(socket_tokio))
}

pub fn create_socket_with_retry(addr: SocketAddr) -> Result<Arc<UdpSocket>> {
    let mut address = addr.clone();
    for _ in 1..1000 {
        match create_socket(address) {
            Ok(socket) => return Ok(socket),
            Err(e) => {
                error!("Failed to bind to {} ({}). Retrying now.", address, e);
                address.set_port(address.port() + 1);
            }
        }
    }
    Err("Could not create socket".to_owned())
}
