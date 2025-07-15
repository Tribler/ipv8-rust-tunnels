from __future__ import annotations

from collections import UserDict
from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from ipv8.messaging.anonymization.community import TunnelCommunity, TunnelSettings
    from ipv8.messaging.anonymization.payload import CellPayload
    from ipv8.types import Address

import asyncio

import ipv8_rust_tunnels.rust_endpoint as rust

from ipv8.messaging.anonymization.crypto import CryptoEndpoint
from ipv8.messaging.interfaces.endpoint import EndpointListener
from ipv8.messaging.interfaces.network_stats import NetworkStat
from ipv8.messaging.interfaces.udp.endpoint import Endpoint, EndpointClosedException, UDPv4Address
from ipv8.taskmanager import TaskManager
from ipv8.util import succeed


class ShadowDict(UserDict):
    def __init__(self, adder, updater, remover):
        self.adder = adder
        self.updater = updater
        self.remover = remover
        super().__init__()

    def __setitem__(self, key, item):
        super().__setitem__(key, item)
        self.adder(key, item)

    def __getitem__(self, key):
        item = super().__getitem__(key)
        if getattr(item, 'dirty', False):
            self.updater(key, item)
            item.dirty = False
        return item

    def __delitem__(self, key):
        super().__delitem__(key)
        self.remover(key)


class RustEndpoint(CryptoEndpoint, Endpoint, TaskManager):
    """
    UDP endpoint implemented in Rust capable of sending/relaying/exiting CellPayloads.
    """

    def __init__(self, port: int = 0, ip: str = "0.0.0.0", worker_threads: int = 4) -> None:
        """
        Create a new RustEndpoint.
        """
        CryptoEndpoint.__init__(self)
        Endpoint.__init__(self)
        TaskManager.__init__(self)
        self.rust_ep = ep = rust.Endpoint(ip, port)
        self.worker_threads = worker_threads
        self.loop = asyncio.get_running_loop()
        self.bytes_up = self.bytes_down = 0
        self.prefix = self.settings = None

        self.circuits = ShadowDict(ep.add_circuit, ep.update_circuit, ep.remove_circuit)
        self.relays = ShadowDict(ep.add_relay, lambda *_: None, ep.remove_relay)
        self.exit_sockets = ShadowDict(ep.add_exit, lambda *_: None, ep.remove_exit)
        
        self.register_task('update_stats', self.update_stats, interval=1)

    def add_prefix_listener(self, listener: EndpointListener, prefix: bytes) -> None:
        """
        Add an EndpointListener to our listeners, only triggers on packets with a specific prefix.

        :raises: IllegalEndpointListenerError if the provided listener is not an EndpointListener
        """
        super().add_prefix_listener(listener, prefix)
        if self.rust_ep.is_open():
            self.rust_ep.set_prefixes(list(self._prefix_map.keys()))

    def remove_listener(self, listener: EndpointListener) -> None:
        """
        Remove a listener from our listeners, if it is registered.
        """
        super().remove_listener(listener)
        if self.rust_ep.is_open():
            self.rust_ep.set_prefixes(list(self._prefix_map.keys()))

    def update_stats(self) -> None:
        """
        Updates the statistics of the routing objects using the most recent data from Rust.
        """
        for circuit in self.circuits.values():
            self.rust_ep.update_circuit_stats(circuit.circuit_id, circuit)

        for relay in self.relays.values():
            self.rust_ep.update_relay_stats(relay.circuit_id, relay)

        for exit_socket in self.exit_sockets.values():
            self.rust_ep.update_exit_stats(exit_socket.circuit_id, exit_socket)

    def get_statistics(self, prefix: bytes) -> dict[int, NetworkStat]:
        """
        Get the message statistics per message identifier for the given prefix.
        """
        result = {}
        for msg_id, counters in self.rust_ep.get_message_statistics(prefix).items():
            stat = result[msg_id] = NetworkStat(msg_id)
            stat.num_up = counters[0]
            stat.num_down = counters[2]
            stat.bytes_up = counters[1]
            stat.bytes_down = counters[3]
        return result

    def enable_community_statistics(self, community_prefix: bytes, enabled: bool) -> None:
        """
        Start tracking stats for packets with the given prefix.
        """
        pass

    def setup_tunnels(self, tunnel_community: TunnelCommunity, settings: TunnelSettings) -> None:
        """
        Set up the TunnelCommunity.
        """
        self.prefix = tunnel_community.get_prefix()
        self.settings = settings
        self.apply_settings()

    def apply_settings(self) -> None:
        """
        Apply tunnels settings to the RustEndpoint. If `RustEndpoint.open` hasn't been called yet,
        the settings will be applied automatically when it is called.
        """
        if self.prefix and self.settings and self.is_open():
            self.rust_ep.set_prefix(self.prefix)
            self.rust_ep.set_prefixes(list(self._prefix_map.keys()))
            self.rust_ep.set_max_relay_early(self.settings.max_relay_early)
            self.rust_ep.set_peer_flags(self.settings.peer_flags)

    def set_max_relay_early(self, max_relay_early: int) -> None:
        """
        Set the maximum number of relay_early cells that are allowed to pass a relay.
        """
        if self.is_open():
            self.rust_ep.set_max_relay_early(max_relay_early)

    def set_peer_flags(self, peer_flags: set[int]) -> None:
        """
        Set peer flags.
        """
        if self.is_open():
            self.rust_ep.set_peer_flags(peer_flags)

    def set_exit_address(self, address: Address) -> None:
        """
        Sets the address that exit sockets should bind to (e.g., ('0.0.0.0', 0)).
        """
        if self.is_open():
            self.rust_ep.set_exit_address(address)

    def create_udp_associate(self, port: int, hops: int) -> int:
        """
        Create a SOCKS5 UDP associate socket using the given port and hop count.
        Returns the port on which the socket was created (in case port 0 was given as argument).
        """
        return self.rust_ep.create_udp_associate(port, hops)

    def close_udp_associate(self, port: int) -> None:
        """
        Close the SOCKS5 UDP associate socket that's bound to the given port.
        """
        return self.rust_ep.close_udp_associate(port)

    def set_udp_associate_default_remote(self, addr: Address) -> None:
        """
        Set the default remote address for all available SOCKS5 UDP associate sockets.
        """
        return self.rust_ep.set_udp_associate_default_remote(addr)

    def get_associated_circuits(self, port: int) -> list[int]:
        """
        Get the circuits for the given UDP associate port.
        """
        return self.rust_ep.get_associated_circuits(port)

    def datagram_received(self, ip: str, port: int, datagram: bytes) -> None:
        """
        Process incoming data that's coming directly from the socket.
        """
        self.bytes_down += len(datagram)
        self.loop.call_soon_threadsafe(self.notify_listeners, (UDPv4Address(ip, port), datagram))

    def send(self, socket_address: Address, packet: bytes) -> None:
        """
        Send a packet to a given address.
        """
        self.assert_open()
        try:
            self.rust_ep.send((str(socket_address[0]), socket_address[1]), packet)
            self.bytes_up += len(packet)
        except (TypeError, ValueError, AttributeError, rust.RustError) as exc:
            self._logger.warning("Dropping packet due to message formatting error: %s", exc)

    def send_cell(self, target_addr: Address, cell: CellPayload) -> None:
        """
        Send the given payload DIRECTLY to the given peer with the appropriate encryption rules.
        """
        packet = cell.to_bin(self.prefix)
        self.rust_ep.send_cell(target_addr, packet)
        self.bytes_up += len(packet)

    def open(self) -> bool:  # noqa: A003
        """
        Open the Endpoint.

        :return: True is the Endpoint was successfully opened, False otherwise.
        """
        self.rust_ep.open(self.datagram_received, self.worker_threads)
        self.apply_settings()
        return succeed(self.rust_ep.is_open())

    async def close(self) -> None:
        """
        Closes the Endpoint.
        """
        await self.shutdown_task_manager()

        if not self.is_open():
            return

        self.rust_ep.close()

    def assert_open(self) -> None:
        """
        Check if we are opened by the programmer and if the underlying transport is fully open.
        """
        if not self.is_open():
            raise EndpointClosedException(self)

    def get_address(self) -> Address:
        """
        Get the address for this Endpoint.
        """
        self.assert_open()
        return self.rust_ep.get_address()

    def is_open(self) -> bool:
        """
        Check if the underlying socket is open.
        """
        return self.rust_ep.is_open()

    def reset_byte_counters(self) -> None:
        """
        Set bytes_up and bytes_down to 0.
        """
        self.bytes_up = 0
        self.bytes_down = 0

    def run_speedtest(self, circuit_id: int, test_time: int, request_size: int,
                      response_size: int, target_rtt: int, callback: Callable, callback_interval: int = 0) -> None:
        """
        Perform a TunnelCommunity speedtest.
        """
        def callback_threadsafe(*args):
            self.loop.call_soon_threadsafe(callback, *args)
        return self.rust_ep.run_speedtest(circuit_id, test_time, request_size,
                                          response_size, target_rtt, callback_threadsafe, callback_interval)
