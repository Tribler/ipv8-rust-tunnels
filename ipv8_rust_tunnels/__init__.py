from typing import TYPE_CHECKING
from . import _rust
from ._rust import (
    __version__,
    PrivateKey,
    PublicKey,
    SessionKeys,
    crypto_auth,
    crypto_auth_verify,
    crypto_box_beforenm,
    generate_rsa_prime,
    generate_safe_prime,
    generate_session_keys,
    is_prime,
    InvalidAddressError,
    NotOpenError,
    TunnelEngine,
    TunnelSettings,
    PEER_FLAG_RELAY,
    PEER_FLAG_EXIT_BT,
    PEER_FLAG_EXIT_IPV8,
    PEER_FLAG_SPEED_TEST,
    PEER_FLAG_EXIT_HTTP
)

if TYPE_CHECKING:
    from .endpoint import Endpoint


def __getattr__(name: str):
    if name == "Endpoint":
        from .endpoint import Endpoint
        return Endpoint
    if hasattr(_rust, name):
        return getattr(_rust, name)
    raise AttributeError(f"module {__name__} has no attribute {name}")


__all__ = [
    "__version__",
    "Endpoint",
    "TunnelEngine",
    "TunnelSettings",
    "PrivateKey",
    "PublicKey",
    "SessionKeys",
    "crypto_auth",
    "crypto_auth_verify",
    "crypto_box_beforenm",
    "generate_rsa_prime",
    "generate_safe_prime",
    "generate_session_keys",
    "is_prime",
    "NotOpenError",
    "InvalidAddressError",
    "PEER_FLAG_RELAY",
    "PEER_FLAG_EXIT_BT",
    "PEER_FLAG_EXIT_IPV8",
    "PEER_FLAG_SPEED_TEST",
    "PEER_FLAG_EXIT_HTTP",
]
