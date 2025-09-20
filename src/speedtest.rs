use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use pyo3::{types::IntoPyDict, PyObject, Python};
use rand::{Rng, RngCore};
use tokio::sync::broadcast;

use crate::{
    payload::{Header, Raw, TestRequestPayload},
    routing::table::RoutingTable,
    util::get_time_ms,
};

pub async fn run_test(
    circuit_id: u32,
    rt: RoutingTable,
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
        cb_task = Some(rt.settings.load().handle.spawn(cb_loop(
            Python::with_gil(|py| callback.clone_ref(py)),
            callback_interval,
            results.clone(),
        )));
    }

    let recv_task = rt.settings.load().handle.spawn(receive_loop(
        rt.settings.load().test_channel.clone(),
        results.clone(),
        rtts.clone(),
    ));

    debug!("Testing circuit {}..", circuit_id);
    let prefix = rt.settings.load().prefix.clone();
    let send_task = rt.settings.load().handle.spawn(send_loop(
        circuit_id,
        prefix,
        rt.clone(),
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
    prefix: Vec<u8>,
    rt: RoutingTable,
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
        let test_request = TestRequestPayload {
            header: Header {
                prefix: prefix.to_vec(),
                msg_id: 21,
                circuit_id,
            },
            identifier: tid,
            response_size,
            request: Raw {
                data: random_data[..request_size as usize].to_vec(),
            },
        };

        match rt.send_cell(circuit_id, &test_request).await {
            Ok(n) => {
                debug!("Sending test-request for circuit {}", circuit_id);
                results
                    .lock()
                    .unwrap()
                    .insert(tid, [get_time_ms() as usize, n, 0, 0]);
            }
            Err(e) => {
                error!("Can't send test-request for circuit {}: {}", circuit_id, e);
                break;
            }
        };
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
