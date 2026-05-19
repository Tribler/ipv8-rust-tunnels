use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use _rust::task_manager::TaskManager;
use _rust::transport::buffer::{Buffer, BufferPool};
use _rust::transport::settings::EndpointSettings;

#[path = "../tests/common.rs"]
mod common;
use common::{create_listener, to_mb};

#[tokio::main]
async fn main() {
    let settings = Arc::new(arc_swap::ArcSwap::from_pointee(EndpointSettings::default()));

    let handle = tokio::runtime::Handle::try_current().unwrap();
    let tm = TaskManager::new(handle);

    let tx_addr = "127.0.0.1:26601".parse().unwrap();
    let tx = create_listener(tx_addr, settings.clone(), &tm);
    let rx_addr = "127.0.0.1:26602".parse().unwrap();
    let rx = create_listener(rx_addr, settings, &tm);
    let settings = EndpointSettings::default();

    let (tx_outbound, rx_outbound) = flume::bounded::<(SocketAddr, Buffer)>(16384);

    for i in 0..settings.recv_tasks {
        let rx_clone = rx.clone();
        tm.spawn(&format!("listen_loop_{}", i), async move {
            let _ = rx_clone.run_listen_loop(i).await;
        });
    }

    for i in 0..settings.send_tasks {
        let rx_outbound_clone = rx_outbound.clone();
        let tx_clone = tx.clone();
        tm.spawn(&format!("send_loop_{}", i), async move {
            let _ = tx_clone.run_send_loop(i, rx_outbound_clone).await;
        });
    }

    let mut producer_tasks = Vec::new();
    let buffer_pool = Arc::new(BufferPool::new(1024, 2048));
    for i in 0..settings.send_tasks {
        let tx_outbound_clone = tx_outbound.clone();
        let buffer_pool_clone = buffer_pool.clone();
        producer_tasks.push(tm.spawn(&format!("producer_loop_{}", i), async move {
            loop {
                if let Ok(buffer) = buffer_pool_clone.pull().await {
                    if tx_outbound_clone.send_async((rx_addr, buffer)).await.is_err() {
                        break;
                    }
                }
            }
        }));
    }

    println!("Running transport benchmark...");
    let start_instant = Instant::now();
    tokio::time::sleep(Duration::from_secs(10)).await;
    producer_tasks.into_iter().for_each(|id| {
        tm.cancel_task(id);
    });
    let elapsed = start_instant.elapsed().as_secs_f64();

    let bytes_up = tx.stats.socket_stats.bytes_up.load(Ordering::Relaxed);
    let bytes_down = rx.stats.socket_stats.bytes_down.load(Ordering::Relaxed);

    println!("\n┌─────────────────────────────────────────────────────────┐");
    println!("│               TRANSPORT BENCHMARK RESULTS               │");
    println!("└─────────────────────────────────────────────────────────┘");
    println!(" Elapsed time:                {:.2} seconds", elapsed);
    println!(" Total data received:         {:.2} MB", to_mb(bytes_down));
    println!(" Speed out:                   {:.2} MB/s", to_mb(bytes_up) / elapsed);
    println!(" Speed in:                    {:.2} MB/s", to_mb(bytes_down) / elapsed);
    println!(" ─────────────────────────────────────────────────────────");
    println!(" Host CPU threads available:  {}", settings.num_threads);
    println!(" Is single-threaded runtime:  {}", settings.single_threaded);
    println!(" Allocated workers:           {}", settings.worker_tasks);
    println!("└─────────────────────────────────────────────────────────┘\n");
}
