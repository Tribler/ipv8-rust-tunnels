use std::net::SocketAddr;

use arc_swap::ArcSwapOption;

use crate::community::routing::circuit::CircuitState;
use crate::notifier::Notifier;
use crate::task_manager::TaskManager;
use crate::{community::speedtest::TestMetric, crypto::keys::PrivateKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TunnelEvent {
    CircuitsNeeded,
    CircuitState,
}

#[derive(Debug)]
pub struct RuntimeContext {
    pub test_channel: flume::Sender<TestMetric>,
    pub test_receiver: flume::Receiver<TestMetric>,
    pub my_sk: ArcSwapOption<PrivateKey>,
    pub my_estimated_wan: ArcSwapOption<SocketAddr>,
    pub notifier: Notifier<TunnelEvent, Option<(u32, CircuitState)>>,
}

impl RuntimeContext {
    pub fn new(task_manager: TaskManager) -> Self {
        let (tx, rx) = flume::bounded::<TestMetric>(4096);
        Self {
            test_channel: tx,
            test_receiver: rx,
            my_sk: ArcSwapOption::const_empty(),
            my_estimated_wan: ArcSwapOption::const_empty(),
            notifier: Notifier::new(task_manager),
        }
    }

    pub fn notify_circuit_state(&self, circuit_id: u32, state: CircuitState) {
        self.notifier.notify(TunnelEvent::CircuitState, Some((circuit_id, state)));
    }

    pub fn get_my_public_key(&self) -> Vec<u8> {
        self.my_sk
            .load()
            .as_ref()
            .and_then(|sk| sk.public_key().ok())
            .and_then(|pk| pk.key_to_bin().ok())
            .unwrap_or_default()
    }
}
