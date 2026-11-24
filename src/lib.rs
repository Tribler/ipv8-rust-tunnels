use std::net::{IpAddr, SocketAddr};

use pyo3::exceptions::{PyException, PyValueError};
use pyo3::{create_exception, prelude::*};

pub mod community;
pub mod crypto;
pub mod dht;
pub mod notifier;
pub mod peer;
pub mod request_cache;
pub mod task_manager;
#[cfg(feature = "transcoder")]
pub mod transcoder;
pub mod transport;
pub mod util;

#[macro_use]
extern crate tracing;

create_exception!(_rust, NotOpenError, PyException);
create_exception!(_rust, InvalidAddressError, PyValueError);

pub fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .with_thread_ids(true)
        .compact()
        .try_init();
}

#[pymodule]
pub fn _rust(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    init_logging();

    m.add_class::<transport::endpoint::Endpoint>()?;
    m.add_class::<transport::settings::PyEndpointSettings>()?;
    m.add("NotOpenError", py.get_type::<NotOpenError>())?;
    m.add("InvalidAddressError", py.get_type::<InvalidAddressError>())?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    m.add_class::<crypto::keys::PyPublicKey>()?;
    m.add_class::<crypto::keys::PyPrivateKey>()?;
    m.add_function(wrap_pyfunction!(crypto::keys::generate_safe_prime, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::keys::generate_rsa_prime, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::keys::is_prime, m)?)?;

    m.add_class::<crypto::dh::PySessionKeys>()?;
    m.add_function(wrap_pyfunction!(crypto::dh::py_generate_session_keys, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::dh::py_crypto_auth, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::dh::py_crypto_auth_verify, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::dh::py_crypto_box_beforenm, m)?)?;

    m.add_class::<community::engine::PyTunnelEngine>()?;
    m.add_class::<community::settings::PyTunnelSettings>()?;

    m.add_class::<community::routing::circuit::PyHopStats>()?;
    m.add_class::<community::routing::circuit::PyCircuitStats>()?;
    m.add_class::<community::routing::relay::PyRelayStats>()?;
    m.add_class::<community::routing::rendezvous::PyRendezvousStats>()?;
    m.add_class::<community::routing::exit::PyExitStats>()?;
    m.add_class::<community::hiddenservices::PySwarmStats>()?;

    m.add("PEER_FLAG_RELAY", community::routing::peer::PeerFlag::Relay as u32)?;
    m.add("PEER_FLAG_EXIT_BT", community::routing::peer::PeerFlag::ExitBt as u32)?;
    m.add("PEER_FLAG_EXIT_IPV8", community::routing::peer::PeerFlag::ExitIpv8 as u32)?;
    m.add("PEER_FLAG_SPEED_TEST", community::routing::peer::PeerFlag::SpeedTest as u32)?;
    m.add("PEER_FLAG_EXIT_HTTP", community::routing::peer::PeerFlag::ExitHttp as u32)?;
    m.add("PEER_FLAG_BACKUP", community::routing::peer::PeerFlag::ExitBackup as u32)?;

    #[cfg(all(feature = "python-extension", feature = "transcoder"))]
    {
        m.add_class::<transcoder::TranscodeServer>()?;
        m.add_class::<transcoder::MediaMetadata>()?;
    }

    Ok(())
}

pub fn parse_address(address: &Bound<'_, PyAny>) -> PyResult<SocketAddr> {
    let ip = address.get_item(0)?.extract::<String>()?;
    let port = address.get_item(1)?.extract::<u16>()?;
    match ip.parse::<IpAddr>() {
        Ok(addr) => Ok(SocketAddr::new(addr.to_canonical(), port)),
        Err(e) => Err(InvalidAddressError::new_err(e.to_string())),
    }
}
