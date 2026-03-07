use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::task::{AbortHandle, Builder, JoinHandle};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

#[derive(Clone, Debug)]
pub struct TaskManager {
    pub handle: Handle,
    tracker: TaskTracker,
    token: CancellationToken,
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

    pub fn spawn<F>(&self, name: &str, future: F) -> JoinHandle<()>
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

        let join_handle = Builder::new()
            .name(name)
            .spawn_on(
                async move {
                    token.run_until_cancelled(future).await;

                    let mut lock = handles.lock().unwrap();
                    lock.remove(&task_id);
                },
                &self.handle,
            )
            .expect("Failed to spawn task");

        let mut lock = self.abort_handles.lock().unwrap();
        lock.insert(task_id, join_handle.abort_handle());

        join_handle
    }

    pub async fn shutdown(self, grace_period_seconds: u64) {
        let grace_period = Duration::from_secs(grace_period_seconds);

        info!("Starting shutdown sequence...");
        self.token.cancel();
        self.tracker.close();

        if let Err(_) = timeout(grace_period, self.tracker.wait()).await {
            info!(
                "Shutdown timed out after {} seconds! Forcing abort of remaining tasks...",
                grace_period_seconds
            );
            let mut handles = self.abort_handles.lock().unwrap();
            for (_, handle) in handles.drain() {
                handle.abort();
            }
        }
        info!("Shutdown completed.");
    }
}
