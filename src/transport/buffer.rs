use std::sync::Arc;

#[derive(Debug)]
pub struct Buffer {
    pub inner: Option<Vec<u8>>,
    pub pool_tx: Option<Arc<flume::Sender<Vec<u8>>>>,
}

impl Buffer {
    pub fn new(buf: Vec<u8>, pool_tx: Option<Arc<flume::Sender<Vec<u8>>>>) -> Self {
        Self { inner: Some(buf), pool_tx }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        if let Some(buf) = self.inner.take() {
            // Empherical buffers don't have a sender.
            if let Some(ref tx) = self.pool_tx {
                if let Err(flume::TrySendError::Full(returned_buf)) = tx.try_send(buf) {
                    warn!("Failed to put buffer back in the pool, rescheduling..");
                    let tx_clone = Arc::clone(tx);
                    tokio::spawn(async move {
                        let _ = tx_clone.send_async(returned_buf).await;
                    });
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct BufferPool {
    tx: Arc<flume::Sender<Vec<u8>>>,
    rx: flume::Receiver<Vec<u8>>,
    buffer_capacity: usize,
}

impl BufferPool {
    pub fn new(pool_size: usize, buffer_capacity: usize) -> Self {
        let (tx, rx) = flume::bounded::<Vec<u8>>(pool_size);
        let tx = Arc::new(tx);

        for _ in 0..pool_size {
            let _ = tx.try_send(vec![0u8; buffer_capacity]);
        }

        Self { tx, rx, buffer_capacity }
    }

    pub async fn pull(&self) -> Result<Buffer, String> {
        match self.rx.recv_async().await {
            Ok(mut buf) => {
                buf.clear();
                buf.resize(self.buffer_capacity, 0);
                Ok(Buffer::new(buf, Some(Arc::clone(&self.tx))))
            }
            Err(_) => Err("BufferPool has disconnected unexpectedly!".to_owned()),
        }
    }

    pub fn sender(&self) -> Arc<flume::Sender<Vec<u8>>> {
        self.tx.clone()
    }
}
