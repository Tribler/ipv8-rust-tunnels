use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::runtime::Handle;
use tokio::task::{AbortHandle, Builder};
use tokio::time::{interval_at, timeout, Instant};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

#[derive(Clone, Debug)]
pub struct TaskManager {
    pub handle: Handle,
    pub tracker: TaskTracker,
    pub token: CancellationToken,
    abort_handles: Arc<Mutex<HashMap<usize, AbortHandle>>>,
    next_id: Arc<Mutex<usize>>,
}

impl TaskManager {
    pub fn new(handle: Handle) -> Self {
        Self {
            handle,
            tracker: TaskTracker::new(),
            token: CancellationToken::new(),
            abort_handles: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(0)),
        }
    }

    pub fn spawn<F>(&self, name: &str, future: F) -> usize
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let token = self.token.clone();
        let handles = self.abort_handles.clone();

        let task_id: usize = {
            let mut id_gen = self.next_id.lock().unwrap();
            let id = *id_gen;
            *id_gen += 1;
            id
        };

        let task_future = async move {
            token.run_until_cancelled(future).await;

            let mut lock = handles.lock().unwrap();
            lock.remove(&task_id);
        };
        let tracked_future = self.tracker.track_future(task_future);

        let join_handle =
            Builder::new().name(name).spawn_on(tracked_future, &self.handle).expect("Failed to spawn task");

        let mut lock = self.abort_handles.lock().unwrap();
        lock.insert(task_id, join_handle.abort_handle());

        task_id
    }

    pub fn spawn_interval<F, Fut>(
        &self,
        name: &str,
        interval_duration: Duration,
        start_now: bool,
        mut f: F,
    ) -> usize
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let start_time = if start_now { Instant::now() } else { Instant::now() + interval_duration };

        let mut interval = interval_at(start_time, interval_duration);
        // Ensure that if execution runs late, missed ticks are skipped.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        self.spawn(name, async move {
            loop {
                interval.tick().await;
                f().await;
            }
        })
    }

    pub fn cancel_task(&self, task_id: usize) -> bool {
        let mut lock = self.abort_handles.lock().unwrap();
        if let Some(handle) = lock.remove(&task_id) {
            handle.abort();
            true
        } else {
            false
        }
    }

    pub async fn shutdown(self, grace_period_seconds: u64) {
        let grace_period = Duration::from_secs(grace_period_seconds);

        debug!("Shutting down TaskManager...");
        self.token.cancel();
        self.tracker.close();

        if let Err(_) = timeout(grace_period, self.tracker.wait()).await {
            debug!(
                "Shutdown timed out after {} seconds! Forcing abort of remaining tasks...",
                grace_period_seconds
            );
            let mut handles = self.abort_handles.lock().unwrap();
            for (_, handle) in handles.drain() {
                handle.abort();
            }
        }
        debug!("TaskManager shutdown completed.");
    }
}
