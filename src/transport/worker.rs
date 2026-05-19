use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pyo3::PyObject;

use crate::community::Community;
use crate::task_manager::TaskManager;
use crate::transport::buffer::Buffer;

pub struct RustWork {
    pub community: Community,
    pub packet: Buffer,
    pub src_addr: SocketAddr,
}

pub struct PythonWork {
    pub packet: Vec<u8>,
    pub src_addr: SocketAddr,
}

pub struct WorkerPool {
    tx_rust: flume::Sender<RustWork>,
    tx_python: flume::Sender<PythonWork>,
    pub rust_processed_count: Arc<AtomicUsize>,
    pub python_processed_count: Arc<AtomicUsize>,
}

impl WorkerPool {
    pub fn start(manager: &TaskManager, num_workers: usize, callback: Option<PyObject>) -> Self {
        let rust_processed_count = Arc::new(AtomicUsize::new(0));
        let python_processed_count = Arc::new(AtomicUsize::new(0));

        let (tx_rust, rx_rust) = flume::bounded::<RustWork>(4096);
        let (tx_python, rx_python) = flume::bounded::<PythonWork>(2048);

        info!("Spawning {} processing tasks", num_workers);
        for i in 0..num_workers {
            let rx_worker = rx_rust.clone();
            let counter_clone = Arc::clone(&rust_processed_count);

            manager.spawn(&format!("rust-crypto-worker-{}", i), async move {
                while let Ok(payload) = rx_worker.recv_async().await {
                    if let Err(e) = payload.community.on_packet(payload.src_addr, payload.packet).await {
                        error!("Error handling packet in Rust worker {}: {:?}", i, e);
                    }
                    counter_clone.fetch_add(1, Ordering::Relaxed);
                }
            });
        }

        let python_counter_clone = Arc::clone(&python_processed_count);

        if let Some(cb) = callback {
            // Use the CancellationToken from the TaskManager.
            // If the TaskManager shuts down, the thread will shutdown as well (in <=100ms).
            let tm_token = manager.token.clone();
            std::thread::Builder::new()
                .name("python-callback-thread".to_string())
                .spawn(move || {
                    while !tm_token.is_cancelled() {
                        // Use a timeout so that we check the token regurarly.
                        match rx_python.recv_timeout(Duration::from_millis(100)) {
                            Ok(payload) => {
                                let ip_str = payload.src_addr.ip().to_string();
                                let port_num = payload.src_addr.port();

                                pyo3::Python::with_gil(|py| {
                                    let py_bytes = pyo3::types::PyBytes::new(py, &payload.packet);
                                    if let Err(e) = cb.call1(py, ((ip_str, port_num), py_bytes)) {
                                        error!("Couldn't call Python callback: {}", e);
                                    }
                                });
                                python_counter_clone.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(flume::RecvTimeoutError::Timeout) => continue,
                            Err(flume::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                })
                .expect("Failed to spawn Python callback thread");
        }

        WorkerPool { tx_rust, tx_python, rust_processed_count, python_processed_count }
    }

    pub fn get_metrics(&self) -> (usize, usize) {
        (
            self.rust_processed_count.load(Ordering::Relaxed),
            self.python_processed_count.load(Ordering::Relaxed),
        )
    }

    pub fn tx_rust(&self) -> flume::Sender<RustWork> {
        self.tx_rust.clone()
    }

    pub fn tx_python(&self) -> flume::Sender<PythonWork> {
        self.tx_python.clone()
    }
}
