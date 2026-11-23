from typing import Any, Callable, Dict, Final, List, Literal, Optional, Set, Tuple

__version__: str

PEER_FLAG_RELAY: Final[int]
PEER_FLAG_EXIT_BT: Final[int]
PEER_FLAG_EXIT_IPV8: Final[int]
PEER_FLAG_SPEED_TEST: Final[int]
PEER_FLAG_EXIT_HTTP: Final[int]
PEER_FLAG_BACKUP: Final[int]

class PublicKey:
    """
    A public key class supporting LibNaCLPK (curve25519), PEM, and DER formats.
    """
    def __init__(self, keystring: bytes) -> None: 
        """Load a public key from LibNaCLPK string, PEM, or DER."""
        ...
    def verify(self, signature: bytes, msg: bytes) -> bool: 
        """Verify a signature for a given message."""
        ...
    def key_to_bin(self) -> bytes: 
        """Export the key to LibNaCLPK binary format or DER."""
        ...
    def key_to_pem(self) -> bytes: 
        """Export the key to PEM format."""
        ...
    def get_signature_length(self) -> int: 
        """Return the expected signature length in bytes."""
        ...
    def get_crypt_pk(self) -> bytes: 
        """Get raw X25519 public key. Raises ValueError if unsupported/invalid."""
        ...
    def curve_name(self) -> str:
        """Return the string name of the curve used by this key (e.g., 'curve25519')."""
        ...

class PrivateKey:
    """
    A private key class supporting curve25519 (LibNaCLSK), X25519, and Generic EC.
    """
    def __init__(self, keystring: bytes) -> None: 
        """Load a private key from LibNaCLSK string, PEM, or DER."""
        ...
    @staticmethod
    def generate(curve_name: str) -> "PrivateKey": 
        """Generate a new keypair (e.g., 'curve25519' or a NIST curve)."""
        ...
    def key_to_bin(self) -> bytes: 
        """Export the key to LibNaCLSK binary format or DER."""
        ...
    def key_to_pem(self) -> bytes: 
        """Export the key to PEM format."""
        ...
    def signature(self, msg: bytes) -> bytes: 
        """Sign a message and return the raw signature bytes."""
        ...
    def get_signature_length(self) -> int: ...
    def pub(self) -> PublicKey: 
        """Derive the public key from this private key."""
        ...
    def diffie_hellman(self, peer_public_key: bytes) -> bytes: 
        """Performs ECDH (X25519 or Generic EC). Raises ValueError if unsupported/invalid."""
        ...
    def get_crypt_pk(self) -> bytes: 
        """Get raw X25519 public key. Raises ValueError if unsupported/invalid."""
        ...
    def curve_name(self) -> str:
        """Return the string name of the curve used by this key (e.g., 'curve25519')."""
        ...

class SessionKeys:
    """Container for HKDF-SHA256 derived keys and salts."""
    key_forward: bytes
    key_backward: bytes
    salt_forward: bytes
    salt_backward: bytes
    salt_explicit_forward: int
    salt_explicit_backward: int

    def encrypt_str(self, content: bytes, direction: int) -> bytes:
        """Encrypt using ChaCha20-Poly1305 (returns salt_explicit + ciphertext + tag)."""
        ...
    def decrypt_str(self, content: bytes, direction: int) -> bytes:
        """Decrypt using ChaCha20-Poly1305 (expects salt_explicit + ciphertext + tag)."""
        ...

class _EndpointSettings:
    """Configuration settings for the Endpoint."""
    prefixes: List[bytes]
    num_threads: int
    single_threaded: bool
    worker_tasks: int
    send_tasks: int
    recv_tasks: int

    def __init__(self) -> None: ...

class _Endpoint:
    """
    High-performance Rust UDP endpoint with SOCKS5 support.
    """
    def __init__(self, listen_addr: str, list_port: int, settings: Optional[_EndpointSettings] = None) -> None: ...
    
    def open(self, callback: Any) -> bool: 
        """Start the Tokio runtime and bind the socket."""
        ...
    def close(self, timeout_secs: int) -> None: 
        """Gracefully shut down the endpoint."""
        ...
    def is_open(self) -> bool: ...
    def get_address(self) -> Tuple[str, int]: ...
    
    def send(self, address: Tuple[str, int], bytes: bytes) -> None: 
        """Send a raw UDP packet."""
        ...
    def send_cell(self, address: Tuple[str, int], bytes: bytes) -> None: 
        """Encrypt and send a tunnel cell through a circuit, relay, or exit."""
        ...

    def get_socket_statistics(self) -> Tuple[int, ...]: ...
    def get_message_statistics(self, prefix: bytes) -> Dict[int, List[int]]: ...

    def set_prefixes(self, prefixes: List[bytes]) -> None: ...
    def get_prefixes(self) -> List[bytes]: ...
	
    def set_debug(self, enable: bool) -> None: ...
    def get_debug(self) -> bool: ...
    def set_level(self, level: str) -> None: ...
    @property
    def debug_port(self) -> int: ...

class NotOpenError(Exception): ...
class InvalidAddressError(Exception): ...

def generate_safe_prime(bit_length: int) -> int: 
    """Generate a secure safe prime as a Python integer."""
    ...
def generate_rsa_prime(bit_length: int) -> int: 
    """Generate a prime number using RSA key generation (useful for large bit lengths)."""
    ...
def is_prime(number: int) -> bool: 
    """Check if a number is probably prime using Miller-Rabin."""
    ...
def generate_session_keys(shared_secret: bytes) -> SessionKeys: 
    """Expand a shared secret into session keys using HKDF-SHA256."""
    ...
def crypto_auth(key: bytes, message: bytes) -> bytes: 
    """Compute a truncated HMAC-SHA512 (first 32 bytes)."""
    ...
def crypto_auth_verify(tag: bytes, key: bytes, message: bytes) -> bool: 
    """Constant-time verification of an HMAC tag."""
    ...
def crypto_box_beforenm(pk: bytes, sk: bytes) -> bytes:
    """Compute a shared secret from a public key and secret key using X25519 and HSalsa20."""
    ...

class TunnelEngine:
    """High-performance multi-hop onion routing tunnel and proxy engine coordinator."""
    def __init__(self) -> None: ...
    def start(self, py_endpoint: Any, my_sk: PrivateKey, config: TunnelSettings) -> None: ...
    def stop(self, timeout_secs: int) -> None: ...
    def set_circuit_state_callback(self, callback: Optional[Callable[[int, Literal["Ready", "Closing"]], Any]]) -> None: ...
    def set_e2e_callback(self, callback: Optional[Callable[..., Any]]) -> None: ...
    def get_dht_info(self) -> Tuple[bytes, int]: ...
    def add_dht_node(self, node_id: bytes, ip: str, port: int) -> None: ...
    def create_socks5_server(self, port: int, hops: int) -> int: ...
    def set_udp_associate_default_remote(self, address: Tuple[str, int], hops: int) -> None: ...
    def get_associated_circuits(self, port: int) -> Tuple[int, ...]: ...
    def get_peers_for_circuit(self, circuit_id: int) -> List[Tuple[str, int]]: ...
    def set_exit_address(self, address: Tuple[str, int]) -> None: ...
    def get_socks5_statistics(self) -> List[Dict[str, Any]]: ...
    def get_tunnel_statistics(self) -> Dict[str, Any]: ...
    def set_settings(self, config: TunnelSettings) -> None: ...
    def get_settings(self) -> TunnelSettings: ...
    def set_peers(self, candidates: Any) -> None: ...
    def set_my_estimated_wan(self, address: Tuple[str, int]) -> None: ...
    def join_swarm(self, info_hash: bytes, hops: int, seeding: bool = False) -> None: ...
    def leave_swarm(self, info_hash: bytes) -> None: ...
    def create_introduction_point(self, info_hash: bytes) -> None: ...
    def has_intro_point(self, info_hash: bytes) -> bool: ...
    def count_circuits(self, ctype: Optional[str] = "DATA", state: Optional[str] = "READY",
                      exit_flags: Optional[List[int]] = None, hops: Optional[int] = None) -> int: ...
    def run_speedtest(self, circuit_id: int, test_time: int, request_size: int, 
                      response_size: int, target_rtt: int, callback: Any, 
                      callback_interval: int) -> None: ...

class TunnelSettings:
    """Configuration settings for the TunnelEngine."""
    prefix: bytes
    prefixes: List[bytes]
    min_circuits: int
    max_circuits: int
    max_joined_circuits: int
    max_relay_early: int
    max_time_inactive: int
    max_time_extending: int
    max_time: int
    max_traffic: int
    next_hop_timeout: int
    exit_addr: str
    default_remotes: Dict[int, str]
    swarm_lookup_interval: int
    swarm_connection_limit: int

    def __init__(self) -> None: ...

    @property
    def peer_flags(self) -> List[int]: ...
    @peer_flags.setter
    def peer_flags(self, raw_flags: Set[int]) -> None: ...

class HopStats:
    address: str
    mid: bytes
    public_key: bytes
    is_verified: bool
    flags: List[int]

class CircuitStats:
    circuit_id: int
    goal_hops: int
    peer: str
    creation_time: int
    state: Literal["Ready", "Extending", "Closing"]
    circuit_type: str
    data_ready: bool
    hops: List[HopStats]
    exit_flags: List[int]
    bytes_up: int
    bytes_down: int
    last_received: int

class ExitStats:
    circuit_id: int
    enabled: bool
    bytes_up: int
    bytes_down: int
    creation_time: int
    is_introduction: bool
    is_rendezvous: bool

class RelayStats:
    circuit_id_fw: int
    circuit_id_bw: int
    is_rendezvous: bool
    bytes_up: int
    bytes_down: int
    creation_time: int

class RendezvousStats:
    circuit_id_dl: int
    circuit_id_sd: int
    peer_dl: str
    peer_sd: str
    bytes_up: int
    bytes_down: int
    creation_time: int

class SwarmStats:
    info_hash: bytes
    num_intro_points: int
    num_seeders: int
    num_connections: int
    num_connections_incomplete: int
    seeding: bool
    last_lookup: int
    bytes_up: int
    bytes_down: int

class MediaMetadata:
    """Metadata extracted from a stream."""
    duration: float
    container: str
    has_video: bool
    video_codec: str
    video_tag: str
    width: int
    height: int
    video_bitrate: int
    fps: float
    has_audio: bool
    audio_codec: str
    audio_tag: str
    audio_sample_rate: int
    audio_channels: int
    pix_fmt: str

    def to_json(self) -> str: ...

class TranscodeServer:
    """HTTP transcoding server backed by FFmpeg."""
    def __init__(self, api_url: str) -> None: ...
    def get_metadata(self, stream_url: str) -> MediaMetadata: ...
    def get_port(self) -> Optional[int]: ...
    def start_server(self, port: int) -> None:
        """Starts the transcode server on the specified port. Blocks until the socket is bound."""
        ...
