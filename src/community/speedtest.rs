use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use pyo3::types::{IntoPyDict, PyDictMethods};
use pyo3::{PyObject, Python};
use rand::{Rng, RngExt};

use crate::community::routing::table::RoutingTable;
use crate::community::serialization::{Raw, TestRequestPayload};
use crate::transport::stats::Stats;
use crate::util::get_time_ms;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TestMetric {
    pub identifier: u32,
    pub len: u16,
}

struct SlidingWindowRttTracker {
    pub slots: [std::sync::atomic::AtomicU16; 16],
    pub cursor: std::sync::atomic::AtomicU32,
}

impl SlidingWindowRttTracker {
    pub fn new() -> Self {
        Self { slots: Default::default(), cursor: std::sync::atomic::AtomicU32::new(0) }
    }

    pub fn add_rtt(&self, rtt_ms: u16) {
        let idx = self.cursor.fetch_add(1, Ordering::Relaxed) as usize & 0xF;
        self.slots[idx].store(rtt_ms, Ordering::Relaxed);
    }

    pub fn get_average_rtt(&self) -> u64 {
        let mut sum: u64 = 0;
        let mut count: u64 = 0;

        for slot in &self.slots {
            let val = slot.load(Ordering::Relaxed) as u64;
            if val > 0 {
                sum += val;
                count += 1;
            }
        }

        if count == 0 {
            0
        } else {
            sum / count
        }
    }
}

pub async fn run_test(
    circuit_id: u32,
    rt: RoutingTable,
    test_time: u16,
    request_size: u16,
    response_size: u16,
    target_rtt: u16,
    callback: PyObject,
    callback_interval: u16,
    stats: Arc<Stats>,
) {
    let rtts = Arc::new(SlidingWindowRttTracker::new());
    let results = Arc::new(DashMap::<u32, [usize; 4]>::with_capacity(32768));

    let start_up = stats.socket_stats.bytes_up.load(Ordering::Relaxed) as usize;
    let start_down = stats.socket_stats.bytes_down.load(Ordering::Relaxed) as usize;
    let anchor = Instant::now();

    let mut tasks = Vec::with_capacity(5);

    if callback_interval > 0 {
        let cb = Python::with_gil(|py| callback.clone_ref(py));
        let stats_clone = stats.clone();
        tasks.push(rt.task_manager.spawn("speedtest_cb", async move {
            loop {
                tokio::time::sleep(Duration::from_millis(callback_interval as u64)).await;
                let elapsed_ms = anchor.elapsed().as_millis() as usize;
                let current_up =
                    stats_clone.socket_stats.bytes_up.load(Ordering::Relaxed) as usize - start_up;
                let current_down =
                    stats_clone.socket_stats.bytes_down.load(Ordering::Relaxed) as usize - start_down;

                let py_dict: PyObject = Python::with_gil(|py| {
                    let dict = pyo3::types::PyDict::new(py);
                    dict.set_item("bytes_sent", current_up).unwrap();
                    dict.set_item("bytes_received", current_down).unwrap();
                    dict.set_item("elapsed_ms", elapsed_ms).unwrap();
                    dict.into()
                });
                let _ = Python::with_gil(|py| cb.call1(py, (py_dict, false)));
            }
        }));
    }

    let receiver_clone = rt.runtime.test_receiver.clone();
    let results_clone = results.clone();
    let rtts_clone = rtts.clone();
    tasks.push(rt.task_manager.spawn("speedtest_recv", async move {
        loop {
            match receiver_clone.recv_async().await {
                Ok(metric) => {
                    debug!("Received response for request {}", metric.identifier);
                    let mut rtt = 0;
                    if let Some((_, result)) = results_clone.remove(&metric.identifier) {
                        let now = get_time_ms() as usize;
                        rtt = now.saturating_sub(result[0]) as u16;
                    };
                    if rtt != 0 {
                        rtts_clone.add_rtt(rtt);
                    }
                }
                Err(_) => {
                    error!("Error while receiving response");
                }
            };
        }
    }));

    debug!("Testing circuit {}..", circuit_id);
    let rt_clone = rt.clone();
    let rtts_clone = rtts.clone();
    let results_clone = results.clone();
    tasks.push(rt.task_manager.spawn("speedtest_send", async move {
        let mut random_data = [0; 2048];
        rand::rng().fill_bytes(&mut random_data);
        let mut test_request = TestRequestPayload {
            circuit_id,
            identifier: 0,
            response_size,
            request: Raw { data: random_data[..request_size as usize].to_vec() },
        };

        loop {
            if rtts_clone.get_average_rtt() > target_rtt.into() {
                tokio::time::sleep(Duration::from_micros(500)).await;
            }

            test_request.identifier = rand::rng().random();

            match rt_clone.send_cell(&test_request, None).await {
                Ok(n) => {
                    debug!("Sending test-request for circuit {}", circuit_id);
                    results_clone.insert(test_request.identifier, [get_time_ms() as usize, n, 0, 0]);
                }
                Err(e) => {
                    error!("Can't send test-request for circuit {}: {}", circuit_id, e);
                    break;
                }
            };
        }
    }));

    debug!("Stopping test for circuit {}..", circuit_id);
    tokio::time::sleep(Duration::from_millis((test_time).into())).await;
    for task in tasks {
        rt.task_manager.cancel_task(task);
    }

    tokio::time::sleep(Duration::from_millis((target_rtt * 2).into())).await;

    let py_dict: PyObject = Python::with_gil(|py| {
        let mut map = HashMap::new();
        let elapsed = anchor.elapsed().as_millis() as usize;
        let up = stats.socket_stats.bytes_up.load(Ordering::Relaxed) as usize - start_up;
        let down = stats.socket_stats.bytes_down.load(Ordering::Relaxed) as usize - start_down;

        map.insert(1u32, [elapsed, up, elapsed, 0]);
        map.insert(2u32, [elapsed, 0, elapsed, down]);
        map.into_py_dict(py).unwrap().into()
    });

    let _ = Python::with_gil(|py| callback.call1(py, (py_dict, true)));
    info!("Finished test for circuit {}", circuit_id);
}
