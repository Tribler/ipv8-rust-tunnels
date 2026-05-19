use std::net::SocketAddr;

use arc_swap::ArcSwapOption;

use crate::{community::speedtest::TestMetric, crypto::keys::PrivateKey};

#[derive(Debug)]
pub struct RuntimeContext {
    pub test_channel: flume::Sender<TestMetric>,
    pub test_receiver: flume::Receiver<TestMetric>,
    pub my_sk: ArcSwapOption<PrivateKey>,
    pub my_estimated_wan: ArcSwapOption<SocketAddr>,
}

impl RuntimeContext {
    pub fn new() -> Self {
        let (tx, rx) = flume::bounded::<TestMetric>(4096);
        Self {
            test_channel: tx,
            test_receiver: rx,
            my_sk: ArcSwapOption::const_empty(),
            my_estimated_wan: ArcSwapOption::const_empty(),
        }
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
