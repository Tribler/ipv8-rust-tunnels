use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct AtomicStat {
    pub num_up: AtomicU64,
    pub num_down: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub last_received: AtomicU64,
}

impl AtomicStat {
    #[inline(always)]
    pub fn add_up(&self, size: usize) {
        self.num_up.fetch_add(1, Ordering::Relaxed);
        self.bytes_up.fetch_add(size as u64, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn add_down(&self, size: usize, now: u64) {
        self.num_down.fetch_add(1, Ordering::Relaxed);
        self.bytes_down.fetch_add(size as u64, Ordering::Relaxed);

        let mut current = self.last_received.load(Ordering::Relaxed);
        while now > current {
            match self.last_received.compare_exchange_weak(current, now, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    pub fn merge(&self, other: &Self) {
        self.num_up.fetch_add(other.num_up.load(Ordering::Relaxed), Ordering::Relaxed);
        self.bytes_up.fetch_add(other.bytes_up.load(Ordering::Relaxed), Ordering::Relaxed);
        self.num_down.fetch_add(other.num_down.load(Ordering::Relaxed), Ordering::Relaxed);
        self.bytes_down.fetch_add(other.bytes_down.load(Ordering::Relaxed), Ordering::Relaxed);
        self.last_received.fetch_max(other.last_received.load(Ordering::Relaxed), Ordering::Relaxed);
    }

    pub fn to_vec(&self) -> Vec<usize> {
        vec![
            self.num_up.load(Ordering::Relaxed) as usize,
            self.bytes_up.load(Ordering::Relaxed) as usize,
            self.num_down.load(Ordering::Relaxed) as usize,
            self.bytes_down.load(Ordering::Relaxed) as usize,
            self.last_received.load(Ordering::Relaxed) as usize,
        ]
    }
}

#[derive(Debug, Default)]
pub struct Stats {
    pub socket_stats: AtomicStat,
    // To increase performance we give the inbound/outbound tasks a separate map.
    pub msg_stats_in: DashMap<[u8; 22], DashMap<u8, Arc<AtomicStat>>>,
    pub msg_stats_out: DashMap<[u8; 22], DashMap<u8, Arc<AtomicStat>>>,
}

impl Stats {
    pub fn new() -> Self {
        Stats {
            socket_stats: AtomicStat::default(),
            msg_stats_in: DashMap::new(),
            msg_stats_out: DashMap::new(),
        }
    }

    pub fn add_up(&self, buf: &[u8], size: usize) {
        self.socket_stats.add_up(size);

        if size >= 23 {
            let community: [u8; 22] = buf[..22].try_into().unwrap();
            let msg_type = buf[22];

            let community_entry = self.msg_stats_out.entry(community).or_default();
            let type_entry = community_entry.entry(msg_type).or_default();
            type_entry.value().add_up(size);
        }
    }

    pub fn add_down(&self, buf: &[u8], size: usize) {
        let now = crate::util::get_time();
        self.socket_stats.add_down(size, now);

        if size >= 23 {
            let community: [u8; 22] = buf[..22].try_into().unwrap();
            let msg_type = buf[22];

            let community_entry = self.msg_stats_in.entry(community).or_default();
            let type_entry = community_entry.entry(msg_type).or_default();
            type_entry.value().add_down(size, now);
        }
    }
}
