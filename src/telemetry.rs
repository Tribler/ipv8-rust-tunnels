use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU8, Ordering};
use std::sync::Once;
use std::time::Duration;

use tracing::metadata::Metadata;
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Layer};

pub static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);
pub static ASSIGNED_CONSOLES_PORT: AtomicU16 = AtomicU16::new(0);
// Default log level to info (3)
pub static CURRENT_TEXT_LEVEL: AtomicU8 = AtomicU8::new(3);

static INIT_GUARD: Once = Once::new();

struct LocalTextFilter;

impl<S: tracing::Subscriber> tracing_subscriber::layer::Filter<S> for LocalTextFilter {
    fn enabled(&self, metadata: &Metadata<'_>, _ctx: &tracing_subscriber::layer::Context<'_, S>) -> bool {
        let target = metadata.target();

        if target.starts_with("tokio") || target.starts_with("runtime") {
            if !DEBUG_ENABLED.load(Ordering::Relaxed) {
                return false;
            }
        }

        let current_level = CURRENT_TEXT_LEVEL.load(Ordering::Relaxed);
        let meta_level = match *metadata.level() {
            tracing::Level::ERROR => 1,
            tracing::Level::WARN => 2,
            tracing::Level::INFO => 3,
            tracing::Level::DEBUG => 4,
            tracing::Level::TRACE => 5,
        };

        meta_level <= current_level
    }
}

struct DebugEnabledFilter;

impl<S: tracing::Subscriber> tracing_subscriber::layer::Filter<S> for DebugEnabledFilter {
    fn enabled(&self, _metadata: &Metadata<'_>, _ctx: &tracing_subscriber::layer::Context<'_, S>) -> bool {
        DEBUG_ENABLED.load(Ordering::Relaxed)
    }
}

pub fn init_telemetry() {
    INIT_GUARD.call_once(|| {
        let probe_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let actual_port = match TcpListener::bind(probe_addr) {
            Ok(listener) => listener.local_addr().unwrap().port(),
            Err(_) => 5555,
        };
        ASSIGNED_CONSOLES_PORT.store(actual_port, Ordering::Relaxed);

        let text_log_layer = match std::env::var("RUST_LOG") {
            Ok(_) => fmt::layer()
                .with_target(false)
                .with_thread_ids(true)
                .with_span_events(fmt::format::FmtSpan::NONE)
                .compact()
                .with_filter(EnvFilter::from_env("RUST_LOG"))
                .boxed(),
            Err(_) => fmt::layer()
                .with_target(false)
                .with_thread_ids(true)
                .with_span_events(fmt::format::FmtSpan::NONE)
                .compact()
                .with_filter(LocalTextFilter)
                .boxed(),
        };

        let console_addr: SocketAddr = format!("127.0.0.1:{}", actual_port).parse().unwrap();
        let console_layer = console_subscriber::ConsoleLayer::builder()
            .server_addr(console_addr)
            .retention(Duration::from_secs(15))
            .spawn()
            .with_filter(DebugEnabledFilter);

        let subscriber = tracing_subscriber::registry().with(text_log_layer).with(console_layer);

        tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set subscriber as the global default");

        tracing::info!("Successfully started telemetry (gRPC server running on port: {})", actual_port);
    });
}
