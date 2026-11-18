use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::hash::Hash;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

use crate::task_manager::TaskManager;

type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
type AsyncCallback<T> = Arc<dyn Fn(T) -> BoxFuture + Send + Sync>;

#[derive(Clone)]
pub struct Notifier<E, T = ()> {
    channels: Arc<ArcSwap<HashMap<E, broadcast::Sender<T>>>>,
    callbacks: Arc<ArcSwap<HashMap<E, Vec<AsyncCallback<T>>>>>,
    tx: mpsc::UnboundedSender<(E, T)>,
    task_manager: TaskManager,
}

impl<E: fmt::Debug, T> fmt::Debug for Notifier<E, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Notifier").field("events", &self.channels.load().keys().collect::<Vec<_>>()).finish()
    }
}

impl<E, T> Notifier<E, T>
where
    E: Eq + Hash + Clone + Send + Sync + 'static,
    T: Clone + Send + Sync + 'static,
{
    pub fn new(task_manager: TaskManager) -> Self {
        let channels = Arc::new(ArcSwap::from_pointee(HashMap::new()));
        let callbacks: Arc<ArcSwap<HashMap<E, Vec<AsyncCallback<T>>>>> =
            Arc::new(ArcSwap::from_pointee(HashMap::new()));
        let (tx, mut rx) = mpsc::unbounded_channel::<(E, T)>();

        let callbacks_clone = callbacks.clone();
        let tm_clone = task_manager.clone();
        task_manager.spawn("event_notifier_dispatcher", async move {
            while let Some((event, data)) = rx.recv().await {
                if let Some(list) = callbacks_clone.load().get(&event) {
                    for cb in list {
                        let cb = cb.clone();
                        let data = data.clone();
                        tm_clone.spawn("event_notifier_callback", async move {
                            cb(data).await;
                        });
                    }
                }
            }
        });

        Self { channels, callbacks, tx, task_manager }
    }

    /// Retrieve an event's broadcast sender, and create one if missing.
    fn get_or_create(&self, event: E) -> broadcast::Sender<T> {
        if let Some(sender) = self.channels.load().get(&event) {
            return sender.clone();
        }

        let (new_sender, _) = broadcast::channel(64);
        self.channels.rcu(|current| {
            let mut next = (**current).clone();
            next.entry(event.clone()).or_insert_with(|| new_sender.clone());
            next
        });

        self.channels.load().get(&event).unwrap().clone()
    }

    /// Notify all listeners and callbacks.
    pub fn notify(&self, event: E, data: T) {
        let _ = self.get_or_create(event.clone()).send(data.clone());
        let _ = self.tx.send((event, data));
    }

    /// Registers an async callback to be spawned whenever `event` fires.
    pub fn on<F, Fut>(&self, event: E, callback: F)
    where
        F: Fn(T) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let cb: AsyncCallback<T> = Arc::new(move |data| Box::pin(callback(data)));
        self.callbacks.rcu(|current| {
            let mut next = (**current).clone();
            next.entry(event.clone()).or_default().push(cb.clone());
            next
        });
    }

    /// Waits for `event` to fire. Returns `None` if `TaskManager` has shutdown while waiting.
    pub fn wait(&self, event: E) -> impl Future<Output = Option<T>> + Send + 'static {
        let mut rx = self.get_or_create(event).subscribe();
        let token = self.task_manager.token.clone();

        async move {
            loop {
                tokio::select! {
                    res = rx.recv() => match res {
                        Ok(data) => return Some(data),
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => return None,
                    },
                    _ = token.cancelled() => return None,
                }
            }
        }
    }

    /// Waits for `event` to fire within `duration`.
    /// Returns `None` on timeout or if `TaskManager` has shutdown while waiting.
    pub fn wait_timeout(
        &self,
        event: E,
        duration: std::time::Duration,
    ) -> impl Future<Output = Option<T>> + Send + 'static {
        let wait_fut = self.wait(event);
        async move { tokio::time::timeout(duration, wait_fut).await.ok().flatten() }
    }
}
