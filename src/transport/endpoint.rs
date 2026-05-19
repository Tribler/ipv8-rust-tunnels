use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use arc_swap::ArcSwap;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyTuple};
use pyo3::IntoPyObjectExt;
use tokio::runtime::Runtime;

use crate::community::engine::PyTunnelEngine;
use crate::task_manager::TaskManager;
use crate::telemetry::{ASSIGNED_CONSOLES_PORT, CURRENT_TEXT_LEVEL, DEBUG_ENABLED};
use crate::transport::buffer::{Buffer, BufferPool};
use crate::transport::listener::PacketListener;
use crate::transport::router::PacketRouter;
use crate::transport::settings::{EndpointSettings, PyEndpointSettings};
use crate::transport::stats::{AtomicStat, Stats};
use crate::transport::worker::WorkerPool;
use crate::{parse_address, NotOpenError};

#[pyclass(name = "_Endpoint")]
pub struct Endpoint {
    pub addr: String,
    pub settings: Arc<ArcSwap<EndpointSettings>>,
    pub tokio_runtime: Option<Runtime>,
    pub tx_outbound: Option<flume::Sender<(SocketAddr, Buffer)>>,
    pub listener: Option<Arc<PacketListener>>,
    pub engine: Option<Py<PyTunnelEngine>>,
    pub task_manager: Option<TaskManager>,
}

#[pymethods]
impl Endpoint {
    #[new]
    #[pyo3(signature = (listen_addr, list_port, settings = None))]
    pub fn new(listen_addr: String, list_port: u16, settings: Option<PyEndpointSettings>) -> Self {
        let native = settings.unwrap_or_default().into_native();
        Endpoint {
            addr: format!("{}:{}", listen_addr, list_port),
            settings: Arc::new(arc_swap::ArcSwap::from_pointee(native)),
            tokio_runtime: None,
            tx_outbound: None,
            listener: None,
            engine: None,
            task_manager: None,
        }
    }

    pub fn open(&mut self, callback: PyObject) -> PyResult<bool> {
        if self.tokio_runtime.is_some() {
            warn!("Endpoint is already open");
            return Ok(false);
        }

        let socket_addr =
            self.addr.parse::<SocketAddr>().map_err(|e| PyValueError::new_err(e.to_string()))?;

        let settings_guard = self.settings.load();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(settings_guard.num_threads)
            .build()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to build Tokio runtime: {e}")))?;

        let _guard = runtime.enter();
        let socket = match crate::util::create_socket_with_retry(socket_addr) {
            Ok(sock) => sock,
            Err(_) => {
                error!("Failed to create Tokio socket on {:?}", socket_addr);
                return Ok(false);
            }
        };

        let local_addr = socket.local_addr().unwrap();
        info!("Tunnel socket listening on: {:?}", local_addr);

        let (tx_outbound, rx_outbound) = flume::bounded::<(SocketAddr, Buffer)>(4096);
        let manager = TaskManager::new(runtime.handle().clone());

        let worker_pool = WorkerPool::start(&manager, settings_guard.worker_tasks, Some(callback));
        let router = Arc::new(PacketRouter::new(
            HashMap::new(),
            self.settings.clone(),
            worker_pool.tx_rust(),
            worker_pool.tx_python(),
        ));

        let pool_max_capacity = settings_guard.worker_tasks * 128;
        let listen_buffer_pool = BufferPool::new(pool_max_capacity, 2048);

        let listener =
            Arc::new(PacketListener::new(socket.clone(), router, Arc::new(Stats::new()), listen_buffer_pool));

        let num_listeners = settings_guard.recv_tasks;
        info!("Spawning {num_listeners} listener loops");
        for i in 0..num_listeners {
            let listener_clone = listener.clone();
            manager.spawn(&format!("udp-listen-loop-{}", i), async move {
                if let Err(e) = listener_clone.run_listen_loop(i).await {
                    error!("Network listener loop {i} crashed: {:?}", e);
                }
            });
        }

        let num_senders = settings_guard.send_tasks;
        info!("Spawning {num_senders} sender loops");
        for i in 0..num_senders {
            let listener_clone = listener.clone();
            let rx_outbound_clone = rx_outbound.clone();
            manager.spawn(&format!("udp-send-loop-{}", i), async move {
                listener_clone.run_send_loop(i, rx_outbound_clone).await;
            });
        }

        info!("Spawning pool health monitor task");
        let listener_monitor = listener.clone();
        manager.spawn("pool-health-monitor", async move {
            listener_monitor.start_pool_monitor(pool_max_capacity).await;
        });

        self.listener = Some(listener);
        self.tx_outbound = Some(tx_outbound);
        self.tokio_runtime = Some(runtime);
        self.task_manager = Some(manager);

        Ok(true)
    }

    pub fn send(&mut self, address: &Bound<'_, PyTuple>, bytes: &Bound<'_, PyBytes>) -> PyResult<()> {
        let socket_addr = parse_address(address)?;
        let packet = bytes.as_bytes().to_vec();
        trace!("Sending packet with {} bytes to {}", packet.len(), socket_addr);

        let tx_outbound =
            self.tx_outbound.as_ref().ok_or_else(|| NotOpenError::new_err("Endpoint is not open"))?;

        let manager =
            self.task_manager.as_ref().ok_or_else(|| NotOpenError::new_err("TaskManager is not open"))?;

        match tx_outbound.try_send((socket_addr, Buffer::new(packet, None))) {
            Ok(_) => {}
            Err(flume::TrySendError::Full((target_addr, returned_work))) => {
                let tx_clone = tx_outbound.clone();
                manager.spawn("send_to_retry", async move {
                    if let Err(e) = tx_clone.send_async((target_addr, returned_work)).await {
                        error!("Failed to reschedule Python packet: {}", e);
                    }
                });
            }
            Err(flume::TrySendError::Disconnected(_)) => {
                error!("Outbound channel was closed unexpectedly");
                return Err(PyRuntimeError::new_err("Outbound channel closed"));
            }
        }
        Ok(())
    }

    pub fn close(&mut self, py: Python<'_>, timeout_secs: u64) -> PyResult<()> {
        info!("Shutting down endpoint");

        info!("Shutting down listener...");
        if let Some(_listener) = self.listener.take() {
            // drop listener
        }
        info!("Shutting down outbound channel...");
        if let Some(_listener) = self.tx_outbound.take() {
            // drop channel
        }

        if let Some(engine_py) = self.engine.take() {
            let engine = engine_py.borrow_mut(py);

            if let Ok(rt) = engine.get_rt() {
                info!("Shutting down endpoint tasks...");
                let manager = rt.task_manager.clone();
                let handle = manager.handle.clone();

                // Release GIL to allow Python to process other tasks.
                py.allow_threads(move || {
                    handle.block_on(async move {
                        manager.shutdown(timeout_secs).await;
                    });
                });
            }

            engine.stop(py, timeout_secs)?;
        }

        if let Some(runtime) = self.tokio_runtime.take() {
            info!("Shutting down Tokio...");
            runtime.shutdown_background();
        }

        Ok(())
    }

    pub fn is_open(&mut self) -> bool {
        self.tokio_runtime.is_some()
    }

    pub fn get_address(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let Some(listener) = &self.listener else {
            return Err(NotOpenError::new_err("Endpoint is not open"));
        };
        let addr = listener.local_addr();
        let ip = addr.ip().to_string().into_py_any(py)?;
        let port = addr.port().into_py_any(py)?;
        Ok(PyTuple::new(py, vec![ip, port])?.into_any().unbind())
    }

    pub fn get_prefixes(&self) -> Vec<Vec<u8>> {
        self.settings.load().prefixes.clone()
    }

    pub fn set_prefixes(&mut self, val: Vec<Vec<u8>>) {
        let mut new_settings = (**self.settings.load()).clone();
        new_settings.prefixes = val;
        self.settings.store(Arc::new(new_settings));
    }

    pub fn get_socket_statistics(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let Some(listener) = &self.listener else {
            return Err(NotOpenError::new_err("Endpoint is not open"));
        };
        let stats_vec = listener.stats().socket_stats.to_vec();
        Ok(PyTuple::new(py, stats_vec)?.into_any().unbind())
    }

    pub fn get_message_statistics(
        &mut self,
        prefix: &Bound<'_, PyBytes>,
        py: Python<'_>,
    ) -> PyResult<PyObject> {
        let Some(listener) = &self.listener else {
            return Err(NotOpenError::new_err("Endpoint is not open"));
        };

        let result = PyDict::new(py);
        let cid: [u8; 22] = match prefix.as_bytes().try_into() {
            Ok(b) => b,
            Err(_) => {
                warn!("Prefix with incorrect length");
                return Ok(result.into_any().unbind());
            }
        };

        let stats = listener.stats();
        let mut merged: HashMap<u8, AtomicStat> = HashMap::new();

        if let Some(msg_id_map) = stats.msg_stats_out.get(&cid) {
            for entry in msg_id_map.iter() {
                let msg_id = *entry.key();
                let stats_record = entry.value();
                merged.entry(msg_id).or_default().merge(stats_record);
            }
        }

        if let Some(msg_id_map) = stats.msg_stats_in.get(&cid) {
            for entry in msg_id_map.iter() {
                let msg_id = *entry.key();
                let stats_record = entry.value();
                merged.entry(msg_id).or_default().merge(stats_record);
            }
        }

        for (key, value) in merged {
            let _ = result.set_item(key, value.to_vec());
        }
        Ok(result.into_any().unbind())
    }

    pub fn set_debug(&self, enable: bool) -> PyResult<()> {
        if enable {
            DEBUG_ENABLED.store(true, Ordering::Relaxed);
            info!("Tokio debugging enabled");
        } else {
            DEBUG_ENABLED.store(false, Ordering::Relaxed);
            info!("Tokio debugging disabled");
        }
        Ok(())
    }

    pub fn get_debug(&self) -> PyResult<bool> {
        Ok(DEBUG_ENABLED.load(Ordering::Relaxed))
    }

    pub fn set_level(&self, level: String) -> PyResult<()> {
        let normalized = level.to_lowercase();
        let level_byte = match normalized.as_str() {
            "off" => 0,
            "error" => 1,
            "warn" => 2,
            "info" => 3,
            "debug" => 4,
            "trace" => 5,
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "Invalid log level. Choose from: trace, debug, info, warn, error, off",
                ))
            }
        };

        CURRENT_TEXT_LEVEL.store(level_byte, Ordering::Relaxed);
        info!("Log level set to: {}", normalized);
        Ok(())
    }

    #[getter]
    pub fn debug_port(&self) -> u16 {
        ASSIGNED_CONSOLES_PORT.load(Ordering::Relaxed)
    }
}
