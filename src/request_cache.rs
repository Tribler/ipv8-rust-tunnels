use std::any::Any;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc::{self, Receiver, Sender};

#[derive(Debug, Clone)]
enum CacheEntry {
    Stream(Sender<Vec<u8>>),
    Identifier(Option<Arc<dyn Any + Send + Sync>>),
}

#[derive(Debug, Clone)]
pub enum CacheResult {
    Stream(Sender<Vec<u8>>),
    Identifier(Option<Arc<dyn Any + Send + Sync>>),
    NotFound,
}

#[derive(Debug, Clone, Default)]
pub struct RequestCache {
    entries: Arc<Mutex<HashMap<(String, u32), CacheEntry>>>,
    sequence: Arc<AtomicU32>,
}

impl RequestCache {
    pub fn new() -> Self {
        Self { entries: Arc::new(Mutex::new(HashMap::new())), sequence: Arc::new(AtomicU32::new(0)) }
    }

    pub fn add<I: Into<u32>>(&self, prefix: String, id: I, buffer: usize) -> (Receiver<Vec<u8>>, CacheGuard) {
        // Registers a streaming request (like HTTP) that receives multiple data parts over time.
        // Returns the data receiver and a `CacheGuard` that automatically removes the entry when dropped.

        let (tx, rx) = mpsc::channel::<Vec<u8>>(buffer);
        let key = (prefix, id.into());

        self.entries.lock().unwrap().insert(key.clone(), CacheEntry::Stream(tx));

        let guard = CacheGuard { cache: Arc::clone(&self.entries), key };

        (rx, guard)
    }

    pub fn add_identifier<I: Into<u32>>(
        &self,
        prefix: String,
        id: I,
        timeout_secs: Option<u64>,
        data: Option<Arc<dyn Any + Send + Sync>>,
    ) {
        // Registers a lightweight identifier (like for Pings) without a data channel.
        // Automatically expires after `timeout_secs` unless manually removed using `.pop()`.

        let key = (prefix, id.into());
        self.entries.lock().unwrap().insert(key.clone(), CacheEntry::Identifier(data));

        if let Some(timeout) = timeout_secs {
            let entries_clone = Arc::clone(&self.entries);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(timeout)).await;
                let mut lock = entries_clone.lock().unwrap();
                if let Some(CacheEntry::Identifier(_)) = lock.get(&key) {
                    lock.remove(&key);
                }
            });
        }
    }

    pub fn has<I: Into<u32>>(&self, prefix: &str, id: I) -> bool {
        let key = (prefix.to_string(), id.into());
        self.entries.lock().unwrap().contains_key(&key)
    }

    pub fn pop<I: Into<u32>>(&self, prefix: &str, id: I) -> CacheResult {
        let mut lock = self.entries.lock().unwrap();
        let key = (prefix.to_string(), id.into());

        match lock.remove(&key) {
            Some(CacheEntry::Stream(tx)) => CacheResult::Stream(tx),
            Some(CacheEntry::Identifier(data)) => CacheResult::Identifier(data),
            None => CacheResult::NotFound,
        }
    }

    pub fn get<I: Into<u32>>(&self, prefix: &str, id: I) -> CacheResult {
        let lock = self.entries.lock().unwrap();
        let key = (prefix.to_string(), id.into());

        match lock.get(&key) {
            Some(CacheEntry::Stream(tx)) => CacheResult::Stream(tx.clone()),
            Some(CacheEntry::Identifier(data)) => CacheResult::Identifier(data.clone()),
            None => CacheResult::NotFound,
        }
    }

    pub fn generate_identifier(&self) -> u32 {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u32;
        nanos ^ seq
    }
}

#[derive(Debug)]
pub struct CacheGuard {
    cache: Arc<Mutex<HashMap<(String, u32), CacheEntry>>>,
    key: (String, u32),
}

impl Drop for CacheGuard {
    fn drop(&mut self) {
        if let Ok(mut lock) = self.cache.lock() {
            if let Some(CacheEntry::Stream(_)) = lock.get(&self.key) {
                lock.remove(&self.key);
            }
        }
    }
}
