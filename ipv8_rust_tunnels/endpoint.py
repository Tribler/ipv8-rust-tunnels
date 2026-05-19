from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ipv8.messaging.interfaces.udp.endpoint import Address

from . import _rust as rust, CircuitState

from ipv8.messaging.interfaces.endpoint import EndpointListener
from ipv8.messaging.interfaces.network_stats import NetworkStat
from ipv8.messaging.interfaces.endpoint import Endpoint as IPv8Endpoint
from ipv8.messaging.interfaces.udp.endpoint import (
    EndpointClosedException,
    UDPv4Address
)
from ipv8.taskmanager import TaskManager


class Endpoint(IPv8Endpoint, TaskManager):
    """
    High-performance Rust-backed UDP endpoint.
    """

    def __init__(self, port: int = 0, ip: str = "0.0.0.0", prefixlen: int = 22) -> None:
        """
        Instantiate a new bare-metal RustEndpoint transport gateway.
        """
        IPv8Endpoint.__init__(self, prefixlen=prefixlen)
        TaskManager.__init__(self)

        self.bytes_up = self.bytes_down = 0

        self.inner = rust._Endpoint(ip, port)
        self.loop = asyncio.get_running_loop()

    async def open(self) -> bool:
        """
        Asynchronously open the socket.
        """
        return await self.loop.run_in_executor(None, self.inner.open, self.datagram_received)

    def datagram_received(self, addr: tuple[str, int], datagram: bytes) -> None:
        """
        Process incoming data that's coming directly from the socket.
        """
        self.loop.call_soon_threadsafe(self.notify_listeners, (UDPv4Address(*addr), datagram))

    async def close(self, grace_period: int = 5) -> None:
        """
        Close the socket and cancel background tasks.
        """
        return await self.loop.run_in_executor(None, self.inner.close, grace_period)

    def is_open(self) -> bool:
        """
        Whether this endpoint is open.
        """
        return self.inner.is_open()

    def assert_open(self) -> None:
        """
        Throw an exception if the endpoint is not open.
        """
        if not self.is_open():
            raise RuntimeError("The socket is currently closed.")

    def get_address(self) -> Address:
        """
        get the local bound socket.
        """
        self.assert_open()
        ip, port = self.inner.get_address()
        return UDPv4Address(ip, port)

    def send(self, socket_address: Address, packet: bytes) -> None:
        """
        Try to send data to some address. No delivery guarantees.
        """
        self.assert_open()
        self.inner.send(socket_address, packet)

    def reset_byte_counters(self) -> None:
        pass

    def enable_community_statistics(self, community_prefix: bytes, enabled: bool) -> None:
        """
        Always enabled. No need to turn this on/off.
        """
        pass

    def get_statistics(self, prefix: bytes) -> dict[int, NetworkStat]:
        """
        Fetch the message statistics per message identifier for the given prefix.
        """
        if not self.is_open():
            return {}

        result = {}
        rust_stats = self.inner.get_message_statistics(prefix)

        for msg_type, counters in rust_stats.items():
            stat = result[msg_type] = NetworkStat(msg_type)
            stat.num_up = counters[0]
            stat.bytes_up = counters[1]
            stat.num_down = counters[2]
            stat.bytes_down = counters[3]
        return result

    def _get_filtered_sum(self, prefix: bytes, array_idx: int, inc_intro: bool, inc_punc: bool, inc_depr: bool) -> int:
        if not self.is_open():
            return 0

        total = 0
        rust_stats = self.inner.get_message_statistics(prefix)
        for msg_id, counters in rust_stats.items():
            if not ((msg_id in self.IDS_DEPRECATED and not inc_depr) or
                    (msg_id in self.IDS_INTRODUCTION and not inc_intro) or
                    (msg_id in self.IDS_PUNCTURE and not inc_punc)):
                total += counters[array_idx]
        return total

    def get_message_sent(self, prefix: bytes, include_introduction: bool = False, include_puncture: bool = False, include_deprecated: bool = False) -> int:
        return self._get_filtered_sum(prefix, 0, include_introduction, include_puncture, include_deprecated)

    def get_bytes_sent(self, prefix: bytes, include_introduction: bool = False, include_puncture: bool = False, include_deprecated: bool = False) -> int:
        return self._get_filtered_sum(prefix, 1, include_introduction, include_puncture, include_deprecated)

    def get_message_received(self, prefix: bytes, include_introduction: bool = False, include_puncture: bool = False, include_deprecated: bool = False) -> int:
        return self._get_filtered_sum(prefix, 2, include_introduction, include_puncture, include_deprecated)

    def get_bytes_received(self, prefix: bytes, include_introduction: bool = False, include_puncture: bool = False, include_deprecated: bool = False) -> int:
        return self._get_filtered_sum(prefix, 3, include_introduction, include_puncture, include_deprecated)

    def add_prefix_listener(self, listener: EndpointListener, prefix: bytes) -> None:
        """
        Add an EndpointListener to our listeners, only triggers on packets with a specific prefix.

        :raises: IllegalEndpointListenerError if the provided listener is not an EndpointListener
        """
        super().add_prefix_listener(listener, prefix)
        self.inner.set_prefixes(list(self._prefix_map.keys()))

    def remove_listener(self, listener: EndpointListener) -> None:
        """
        Remove a listener from our listeners, if it is registered.
        """
        super().remove_listener(listener)
        self.inner.set_prefixes(list(self._prefix_map.keys()))

    def __getattr__(self, item: str) -> Any:
        """
        Routes getattr lookups straight to the underlying Rust Endpoint.
        """
        inner_obj = self.__dict__.get("inner")
        if inner_obj is None:
            raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{item}'")
        return getattr(inner_obj, item)
