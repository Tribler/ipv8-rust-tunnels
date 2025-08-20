use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use tokio::sync::mpsc::{Receiver, Sender};

#[derive(Debug, Clone)]
pub struct RequestCache {
    channels: Arc<Mutex<HashMap<(String, u32), Sender<Vec<u8>>>>>,
}

impl RequestCache {
    pub fn new() -> Self {
        Self {
            channels: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add(&mut self, prefix: String, number: u32, buffer: usize) -> Receiver<Vec<u8>> {
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(buffer);
        self.channels.lock().unwrap().insert((prefix, number), tx);
        rx
    }

    pub fn get(&mut self, prefix: String, number: u32) -> Option<Sender<Vec<u8>>> {
        self.channels.lock().unwrap().get(&(prefix, number)).cloned()
    }

    pub fn pop(&mut self, prefix: String, number: u32) -> Option<Sender<Vec<u8>>> {
        self.channels.lock().unwrap().remove(&(prefix, number))
    }
}
