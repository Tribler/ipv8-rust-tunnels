use std::time::{SystemTime, UNIX_EPOCH};

pub type Result<T> = std::result::Result<T, String>;

pub fn get_time() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(time) => time.as_secs(),
        Err(error) => {
            error!("Failed to get system time: {}", error);
            0
        }
    }
}
