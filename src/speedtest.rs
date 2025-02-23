use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use arc_swap::ArcSwap;
use pyo3::{types::IntoPyDict, PyObject, Python};
use rand::{Rng, RngCore};
use tokio::{net::UdpSocket, sync::broadcast};

use crate::{routing::circuit::Circuit, socket::TunnelSettings, util::get_time_ms};

pub async fn run_test(
    settings: Arc<ArcSwap<TunnelSettings>>,
    circuit_id: u32,
    circuits: Arc<Mutex<HashMap<u32, Circuit>>>,
    socket: Arc<UdpSocket>,
    test_time: u16,
    request_size: u16,
    response_size: u16,
    target_rtt: u16,
    callback: PyObject,
    callback_interval: u16,
) {
    let rtts = Arc::new(Mutex::new(Vec::<u16>::new()));
    let results = Arc::new(Mutex::new(HashMap::new()));

    let mut cb_task = None;
    if callback_interval > 0 {
        cb_task = Some(settings.load().handle.spawn(cb_loop(
            Python::with_gil(|py| callback.clone_ref(py)),
            callback_interval,
            results.clone(),
        )));
    }

    let recv_task = settings.load().handle.spawn(receive_loop(
        settings.load().test_channel.clone(),
        results.clone(),
        rtts.clone(),
    ));

    debug!("Testing circuit {}..", circuit_id);
    let prefix = settings.load().prefix.clone();
    let send_task = settings.load().handle.spawn(send_loop(
        circuit_id,
        circuits.clone(),
        prefix,
        socket.clone(),
        request_size,
        response_size,
        target_rtt,
        results.clone(),
        rtts.clone(),
    ));

    debug!("Stopping test for circuit {}..", circuit_id);
    tokio::time::sleep(Duration::from_millis((test_time).into())).await;
    send_task.abort();
    recv_task.abort();
    if let Some(task) = cb_task {
        task.abort();
    };

    tokio::time::sleep(Duration::from_millis((target_rtt * 2).into())).await;
    let _ = Python::with_gil(|py| {
        callback.call1(py, (results.lock().unwrap().clone().into_py_dict(py)?, true))
    });
    debug!("Finished test for circuit {}", circuit_id);
}

pub async fn receive_loop(
    msg_tx: broadcast::Sender<(u32, usize)>,
    results: Arc<Mutex<HashMap<u32, [usize; 4]>>>,
    rtts: Arc<Mutex<Vec<u16>>>,
) {
    let mut msg_rx = msg_tx.subscribe();

    loop {
        match msg_rx.recv().await {
            Ok((tid, n)) => {
                debug!("Received response for request {}", tid);
                let mut rtt = 0;
                if let Some(result) = results.lock().unwrap().get_mut(&tid) {
                    result[2] = get_time_ms() as usize;
                    result[3] = n;
                    rtt = (result[2] - result[0]) as u16;
                };
                if rtt != 0 {
                    rtts.lock().unwrap().push(rtt);
                }
            }
            Err(_) => {
                error!("Error while receiving response");
            }
        };
    }
}

pub async fn send_loop(
    circuit_id: u32,
    circuits: Arc<Mutex<HashMap<u32, Circuit>>>,
    prefix: Vec<u8>,
    socket: Arc<UdpSocket>,
    request_size: u16,
    response_size: u16,
    target_rtt: u16,
    results: Arc<Mutex<HashMap<u32, [usize; 4]>>>,
    rtts: Arc<Mutex<Vec<u16>>>,
) {
    let mut random_data = [0; 2048];
    rand::rng().fill_bytes(&mut random_data);

    loop {
        let mut sum: u16 = 0;
        if rtts.lock().unwrap().len() > 10 {
            sum = rtts.lock().unwrap().iter().rev().take(10).sum();
        }
        if sum / 10 > target_rtt {
            tokio::time::sleep(Duration::from_millis(0)).await;
        }

        let tid: u32 = rand::rng().random();

        let test_request = [
            prefix.to_vec(),
            vec![0],
            circuit_id.to_be_bytes().to_vec(),
            vec![0, 0, 21],
            tid.to_be_bytes().to_vec(),
            response_size.to_be_bytes().to_vec(),
            random_data[..request_size as usize].to_vec(),
        ]
        .concat();

        let (encrypted, target) = match circuits.lock().unwrap().get_mut(&circuit_id) {
            Some(circuit) => {
                let Ok(encrypted) = circuit.encrypt_outgoing_cell(test_request, 8) else {
                    error!("Can't encrypt cell for circuit {}", circuit_id);
                    break;
                };
                (encrypted, circuit.peer.clone())
            }
            None => {
                error!("Can't find circuit {}", circuit_id);
                break;
            }
        };

        if let Ok(n) = socket.send_to(&encrypted, target).await {
            results
                .lock()
                .unwrap()
                .insert(tid, [get_time_ms() as usize, n, 0, 0]);
        }
    }
}

pub async fn cb_loop(
    callback: PyObject,
    cb_interval: u16,
    results: Arc<Mutex<HashMap<u32, [usize; 4]>>>,
) {
    loop {
        tokio::time::sleep(Duration::from_millis(cb_interval as u64)).await;
        debug!("Calling Python callback (interval={})", cb_interval);
        let _ = Python::with_gil(|py| {
            callback.call1(py, (results.lock().unwrap().clone().into_py_dict(py)?, false))
        });
    }
}
