use std::{
    collections::HashMap,
    io::Cursor,
    sync::{Arc, Mutex},
    time::Duration,
};

use pyo3::{types::IntoPyDict, PyObject, Python};
use rand::{Rng, RngCore};
use socks5_proto::{Address, UdpHeader};
use tokio::{
    net::UdpSocket,
    sync::{broadcast, oneshot, OwnedSemaphorePermit, Semaphore},
};

use crate::util;

pub async fn run_speedtest(
    server_addr: String,
    associate_port: u16,
    num_packets: usize,
    request_size: u16,
    response_size: u16,
    timeout_ms: usize,
    window_size: usize,
    callback: PyObject,
) {
    let (socket_tx, socket_rx) = oneshot::channel();

    let msg_tx = tokio::sync::broadcast::Sender::new(window_size);
    let recv_task = tokio::spawn(receive_and_broadcast(associate_port, socket_tx, msg_tx.clone()));
    let socket = match socket_rx.await {
        Ok(socket) => socket,
        Err(e) => {
            error!("Error while receiving speedtest socket: {}. Aborting test.", e);
            return;
        }
    };

    let semaphore = Arc::new(Semaphore::new(window_size));
    let results = Arc::new(Mutex::new(HashMap::new()));

    debug!("Sending packets with window={}", window_size);

    for _ in 0..num_packets {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        tokio::spawn(send_and_wait(
            Address::SocketAddress(server_addr.parse().unwrap()),
            socket.clone(),
            request_size,
            response_size,
            timeout_ms,
            msg_tx.subscribe(),
            results.clone(),
            permit,
        ));
    }

    debug!("All {} packets sent!", num_packets);
    tokio::time::sleep(Duration::from_millis(timeout_ms.try_into().unwrap())).await;
    recv_task.abort();
    let _ =
        Python::with_gil(|py| callback.call1(py, (results.lock().unwrap().clone().into_py_dict(py),)));
}

pub async fn receive_and_broadcast(
    associate_port: u16,
    socket_tx: oneshot::Sender<Arc<UdpSocket>>,
    tx: broadcast::Sender<(u32, usize)>,
) {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let _ = socket.connect(format!("127.0.0.1:{}", associate_port)).await;
    let _ = socket_tx.send(socket.clone());

    let mut buf = [0; 2048];
    loop {
        match socket.recv(&mut buf).await {
            Ok(n) => {
                let mut packet = &buf[..n];
                // Strip SOCKS5 header
                let Ok(header) = UdpHeader::read_from(&mut Cursor::new(packet)).await else {
                    error!("Failed to decode SOCKS5 header address");
                    continue;
                };
                packet = &packet[header.serialized_len()..];

                // Payload format: 'd' + 4-byte transaction ID + the exit IP + payload + 'e'
                if packet.len() < 13 {
                    error!("Dropping packet (response too small");
                    continue;
                }

                // Broadcast transaction ID
                let tid = u32::from_be_bytes(packet[1..5].try_into().unwrap());
                let _ = tx.send((tid, n));
                debug!("Broadcasting response for request {}", tid);
            }
            Err(ref e) if e.kind() == tokio::io::ErrorKind::WouldBlock => {}
            Err(e) => error!("Error while reading socket: {}", e),
        }
    }
}

pub async fn send_and_wait(
    target: Address,
    socket: Arc<UdpSocket>,
    request_size: u16,
    response_size: u16,
    timeout_ms: usize,
    mut rx: broadcast::Receiver<(u32, usize)>,
    results: Arc<Mutex<HashMap<u32, [usize; 4]>>>,
    _: OwnedSemaphorePermit,
) {
    let mut random_data = [0; 2048];
    rand::thread_rng().fill_bytes(&mut random_data);
    let payload = &random_data[..request_size as usize];
    let tid: u32 = rand::thread_rng().gen();
    let header = UdpHeader::new(0, target.clone());
    let mut socks5_pkt = Vec::with_capacity(header.serialized_len());
    if let Err(e) = header.write_to(&mut socks5_pkt).await {
        error!("Error while writing SOCKS5 header: {}", e);
        return;
    };
    socks5_pkt.extend_from_slice(&[b'd']);
    socks5_pkt.extend_from_slice(&tid.to_be_bytes());
    socks5_pkt.extend_from_slice(&response_size.to_be_bytes());
    socks5_pkt.extend_from_slice(&payload);
    socks5_pkt.extend_from_slice(&[b'e']);

    match socket.send(&socks5_pkt).await {
        Ok(size) => {
            debug!("Sent request {} ({} bytes)", tid, size);
            results
                .lock()
                .unwrap()
                .insert(tid, [util::get_time_ms() as usize, size, 0, 0]);
            let wait_for_tid = async {
                loop {
                    match rx.recv().await {
                        Ok((tid_received, n)) => {
                            debug!("Received {}, looking for {}", tid_received, tid);
                            if tid_received == tid {
                                debug!("Received response for request {}", tid);
                                if let Some(result) = results.lock().unwrap().get_mut(&tid) {
                                    result[2] = util::get_time_ms() as usize;
                                    result[3] = n;
                                    break;
                                };
                            }
                        }
                        Err(_) => {}
                    }
                }
            };
            if let Err(_) =
                tokio::time::timeout(Duration::from_millis(timeout_ms.try_into().unwrap()), wait_for_tid)
                    .await
            {
                warn!("Request {} timedout", tid);
            }
        }
        Err(ref e) if e.kind() == tokio::io::ErrorKind::WouldBlock => {}
        Err(e) => error!("Error while writing to socket: {}", e),
    };
}
