use std::thread;

use pyo3::prelude::*;
use tokio::runtime::{Handle, RuntimeFlavor};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSettings {
    pub prefixes: Vec<Vec<u8>>,
    pub num_threads: usize,
    pub single_threaded: bool,
    pub worker_tasks: usize,
    pub send_tasks: usize,
    pub recv_tasks: usize,
}

impl Default for EndpointSettings {
    fn default() -> Self {
        let num_threads = thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
        let single_threaded = Handle::try_current()
            .map(|h| h.runtime_flavor() == RuntimeFlavor::CurrentThread)
            .unwrap_or(false);

        let (worker_tasks, send_tasks, recv_tasks) = if single_threaded {
            (1, 1, 1)
        } else {
            let scale_threads = num_threads.min(16);
            ((scale_threads / 2).max(1), (scale_threads / 4).min(2).max(1), (scale_threads / 4).min(2).max(1))
        };

        EndpointSettings {
            prefixes: vec![],
            num_threads,
            single_threaded,
            worker_tasks,
            send_tasks,
            recv_tasks,
        }
    }
}

impl EndpointSettings {
    pub fn new() -> Self {
        Self::default()
    }
}

#[pyclass(name = "EndpointSettings", get_all, set_all)]
#[derive(Debug, Clone)]
pub struct PyEndpointSettings {
    pub prefixes: Vec<Vec<u8>>,
    pub num_threads: usize,
    pub single_threaded: bool,
    pub worker_tasks: usize,
    pub send_tasks: usize,
    pub recv_tasks: usize,
}

impl Default for PyEndpointSettings {
    fn default() -> Self {
        Self::from_native(&EndpointSettings::default())
    }
}

#[pymethods]
impl PyEndpointSettings {}

impl PyEndpointSettings {
    pub fn into_native(&self) -> EndpointSettings {
        EndpointSettings {
            prefixes: self.prefixes.clone(),
            num_threads: self.num_threads,
            single_threaded: self.single_threaded,
            worker_tasks: self.worker_tasks,
            send_tasks: self.send_tasks,
            recv_tasks: self.recv_tasks,
        }
    }

    pub fn from_native(native: &EndpointSettings) -> Self {
        PyEndpointSettings {
            prefixes: native.prefixes.clone(),
            num_threads: native.num_threads,
            single_threaded: native.single_threaded,
            worker_tasks: native.worker_tasks,
            send_tasks: native.send_tasks,
            recv_tasks: native.recv_tasks,
        }
    }
}
