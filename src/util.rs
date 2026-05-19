use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use socks5_proto::handshake::Method;
use socks5_proto::{Address as Socks5Address, Command, Reply, Request, Response};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;

use crate::community::serialization::Address;

pub type Result<T> = std::result::Result<T, String>;

#[derive(Debug)]
pub struct Future<T> {
    tx: watch::Sender<Option<T>>,
    rx: watch::Receiver<Option<T>>,
}

impl<T> Future<T>
where
    T: Clone,
{
    pub fn new() -> Self {
        let (tx, rx) = watch::channel(None);
        Self { tx, rx }
    }

    pub fn set(&self, value: T) -> Result<()> {
        if self.rx.borrow().is_some() {
            return Err("cannot modify a future that has already been set".to_owned());
        }
        let _ = self.tx.send(Some(value));
        Ok(())
    }

    pub async fn result(&self) -> T {
        let mut rx = self.rx.clone();
        while rx.borrow().is_none() {
            let _ = rx.changed().await;
        }

        let x = rx.borrow().as_ref().unwrap().clone();
        x
    }

    pub async fn result_timeout(&self, duration: Duration) -> Result<T> {
        match tokio::time::timeout(duration, self.result()).await {
            Ok(value) => Ok(value),
            Err(_) => Err(format!("future resolution timed out after {} seconds", duration.as_secs_f64())),
        }
    }
}

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

pub async fn send_tcp_request(target: &Address, request: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let stream_result = match target {
        Address::V4(addr) => TcpStream::connect(addr).await,
        Address::V6(addr) => TcpStream::connect(addr).await,
        Address::DomainAddress(_, _) => {
            TcpStream::connect((target.hostname().unwrap_or_default(), target.port())).await
        }
    };
    let Ok(mut stream) = stream_result else {
        return Err(format!("error creating TCP stream"));
    };

    match stream.write_all(request).await {
        Err(e) => return Err(format!("error writing to TCP stream: {}", e)),
        _ => {}
    }

    let mut reader = BufReader::new(stream);
    let mut headers = String::new();
    loop {
        match reader.read_line(&mut headers).await {
            Ok(bytes) => {
                if bytes < 3 {
                    break;
                }
            }
            Err(e) => return Err(format!("{}", e)),
        }
    }

    let mut chunked = false;
    let mut content_length = 0;
    for header in headers.split("\n") {
        if header.starts_with("Content-Length") {
            for part in header.split(":") {
                if !(part.starts_with("Content-Length")) {
                    content_length = part.trim().parse::<usize>().unwrap();
                }
            }
        }
        if header.starts_with("Transfer-Encoding: chunked") {
            chunked = true;
        }
    }

    if content_length > 0 {
        // Read content-length bytes
        let mut buffer = vec![0; content_length];
        match reader.read_exact(&mut buffer).await {
            Ok(bytes) => {
                let body = buffer[..bytes].to_vec();
                return Ok((vec![headers.as_bytes(), &body].concat(), body));
            }
            Err(e) => return Err(format!("{}", e)),
        }
    }

    // Read the remaining bytes
    let mut remainder: Vec<u8> = Vec::new();
    loop {
        let mut buf = [0; 4096];
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => remainder.extend_from_slice(&buf[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(format!("{}", e)),
        }
    }

    if !chunked {
        return Ok((vec![headers.as_bytes(), &remainder].concat(), remainder));
    }

    // Convert chunks
    let mut chunk_reader = BufReader::new(&*remainder);
    let mut http_body = vec![];
    loop {
        let mut size_string = String::new();
        match chunk_reader.read_line(&mut size_string).await {
            Ok(bytes) => {
                if bytes < 3 {
                    continue;
                }

                let chunk_size = match usize::from_str_radix(&size_string.trim(), 16) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => return Err(format!("failed to read chunk size")),
                };
                let mut chunk = vec![0_u8; chunk_size];
                let Ok(_) = chunk_reader.read(&mut chunk).await else {
                    return Err(format!("failed to read chunk"));
                };
                http_body.extend_from_slice(&chunk);
            }
            Err(e) => return Err(format!("{}", e)),
        }
    }

    return Ok((vec![headers.as_bytes(), &remainder].concat(), http_body));
}

pub fn to_hex<T: AsRef<[u8]>>(bytes: T) -> String {
    bytes.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
}

pub async fn start_socks5_client(
    proxy_addr: SocketAddr,
    target_addr: Option<SocketAddr>,
) -> Result<(UdpSocket, TcpStream)> {
    let mut tcp_stream = TcpStream::connect(proxy_addr)
        .await
        .map_err(|e| format!("failed to connect to SOCKS5 proxy {}: {}", proxy_addr, e))?;

    tcp_stream
        .write_all(&[0x05, 0x01, Method::NONE.into()])
        .await
        .map_err(|e| format!("failed to transmit SOCKS5 greeting sequence: {}", e))?;

    let mut response = [0u8; 2];
    tcp_stream
        .read_exact(&mut response)
        .await
        .map_err(|e| format!("failed to read SOCKS5 authentication response: {}", e))?;

    if response[0] != 0x05 || response[1] != u8::from(Method::NONE) {
        return Err("failed to connect to SOCKS5 server: authentication rejected".into());
    }

    let bind_addr = target_addr
        .unwrap_or_else(|| SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0));

    let cmd_req =
        Request::new(Command::Associate, Socks5Address::from(Socks5Address::SocketAddress(bind_addr)));

    cmd_req
        .write_to(&mut tcp_stream)
        .await
        .map_err(|e| format!("failed to write UDP associate request: {}", e))?;

    let cmd_resp = Response::read_from(&mut tcp_stream)
        .await
        .map_err(|e| format!("failed to read UDP associate response: {}", e))?;

    if cmd_resp.reply != Reply::Succeeded {
        return Err(format!("failed to create UDP associate: {:?}", cmd_resp.reply));
    }

    let associate_addr = match cmd_resp.address {
        Socks5Address::SocketAddress(addr) => addr,
        Socks5Address::DomainAddress(domain, port) => {
            tokio::net::lookup_host(format!("{}:{}", String::from_utf8_lossy(&domain), port))
                .await
                .map_err(|e| format!("failed to perform DNS lookup: {}", e))?
                .next()
                .ok_or_else(|| "failed to resolve domain address: no host".to_owned())?
        }
    };

    let associate_socket =
        UdpSocket::bind("127.0.0.1:0").await.map_err(|e| format!("failed to bind UDP socket: {}", e))?;

    associate_socket
        .connect(associate_addr)
        .await
        .map_err(|e| format!("failed to connect UDP socket to proxy: {}", e))?;

    Ok((associate_socket, tcp_stream))
}
