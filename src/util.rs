use std::{
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpStream, UdpSocket},
};

use crate::payload::Address;

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

pub async fn send_tcp_request(target: &Address, request: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let stream_result = match target {
        Address::V4(addr) => TcpStream::connect(addr).await,
        Address::V6(addr) => TcpStream::connect(addr).await,
        Address::DomainAddress((domain, port)) => {
            TcpStream::connect((String::from_utf8_lossy(domain).to_string(), port.clone())).await
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
