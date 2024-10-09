use std::collections::HashMap;

#[derive(Default)]
pub struct Stat {
    pub num_up: usize,
    pub num_down: usize,
    pub bytes_up: usize,
    pub bytes_down: usize,
}

impl Stat {
    pub fn new() -> Self {
        Default::default()
    }

    fn add_up(&mut self, size: usize) {
        self.num_up += 1;
        self.bytes_up += size;
    }

    fn add_down(&mut self, size: usize) {
        self.num_down += 1;
        self.bytes_down += size;
    }

    pub fn to_vec(&self) -> Vec<usize> {
        vec![self.num_up, self.bytes_up, self.num_down, self.bytes_down]
    }
}

pub struct Stats {
    pub socket_stats: Stat,
    pub msg_stats: HashMap<[u8; 22], HashMap<u8, Stat>>,
}

impl Stats {
    pub fn new() -> Self {
        Stats {
            socket_stats: Stat::new(),
            msg_stats: HashMap::new(),
        }
    }

    pub fn add_up(&mut self, buf: &[u8], size: usize) {
        self.socket_stats.add_up(size);

        if size >= 23 {
            let community: [u8; 22] = buf[..22].try_into().unwrap();
            self.msg_stats
                .entry(community)
                .or_insert(HashMap::new())
                .entry(buf[22])
                .or_insert(Stat::new())
                .add_up(size);
        }
    }

    pub fn add_down(&mut self, buf: &[u8], size: usize) {
        self.socket_stats.add_down(size);

        if size >= 23 {
            let community: [u8; 22] = buf[..22].try_into().unwrap();
            self.msg_stats
                .entry(community)
                .or_insert(HashMap::new())
                .entry(buf[22])
                .or_insert(Stat::new())
                .add_down(size);
        }
    }
}
