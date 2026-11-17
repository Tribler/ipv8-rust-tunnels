use std::net::SocketAddr;

use arc_swap::ArcSwapOption;

use crate::community::routing::circuit::CircuitState;
use crate::{community::speedtest::TestMetric, crypto::keys::PrivateKey};

#[derive(Debug)]
pub struct RuntimeContext {
    pub test_channel: flume::Sender<TestMetric>,
    pub test_receiver: flume::Receiver<TestMetric>,
    pub circuit_state_tx: flume::Sender<(u32, CircuitState)>,
    pub circuit_state_rx: flume::Receiver<(u32, CircuitState)>,
    pub my_sk: ArcSwapOption<PrivateKey>,
    pub my_estimated_wan: ArcSwapOption<SocketAddr>,
}

impl RuntimeContext {
    pub fn new() -> Self {
        let (tx, rx) = flume::bounded::<TestMetric>(4096);
        let (state_tx, state_rx) = flume::bounded::<(u32, CircuitState)>(256);
        Self {
            test_channel: tx,
            test_receiver: rx,
            circuit_state_tx: state_tx,
            circuit_state_rx: state_rx,
            my_sk: ArcSwapOption::const_empty(),
            my_estimated_wan: ArcSwapOption::const_empty(),
        }
    }

    pub fn notify_circuit_state(&self, circuit_id: u32, state: CircuitState) {
        let _ = self.circuit_state_tx.try_send((circuit_id, state));
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
