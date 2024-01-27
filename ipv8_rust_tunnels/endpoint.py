from __future__ import annotations

from collections import UserDict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ipv8.messaging.anonymization.community import TunnelCommunity, TunnelSettings
    from ipv8.messaging.anonymization.payload import CellPayload
    from ipv8.types import Address

import asyncio

import ipv8_rust_tunnels.rust_endpoint as rust

from ipv8.messaging.anonymization.crypto import CryptoEndpoint
from ipv8.messaging.interfaces.udp.endpoint import Endpoint, EndpointClosedException, UDPv4Address
from ipv8.taskmanager import TaskManager


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

    def __init__(self, port=0, ip="0.0.0.0", worker_threads=4):
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

    def update_stats(self):
        for circuit in self.circuits.values():
            self.rust_ep.update_circuit_stats(circuit.circuit_id, circuit)

        for relay in self.relays.values():
            self.rust_ep.update_relay_stats(relay.circuit_id, relay)

        for exit_socket in self.exit_sockets.values():
            self.rust_ep.update_exit_stats(exit_socket.circuit_id, exit_socket)

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
            self.rust_ep.set_max_relay_early(self.settings.max_relay_early)
            self.rust_ep.set_peer_flags(self.settings.peer_flags)

    def set_max_relay_early(self, max_relay_early: int) -> None:
        """
        Set the maximum number of relay_early cells that are allowed to pass a relay.
        """
        if self.is_open():
            self.rust_ep.set_max_relay_early(max_relay_early)

    def set_peer_flags(self, max_relay_early: int) -> None:
        """
        Set peer flags.
        """
        if self.is_open():
            self.rust_ep.set_peer_flags(max_relay_early)

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

    async def open(self) -> bool:  # noqa: A003
        """
        Open the Endpoint.

        :return: True is the Endpoint was successfully opened, False otherwise.
        """
        self.rust_ep.open(self.datagram_received, self.worker_threads)
        self.apply_settings()
        return self.rust_ep.is_open()

    def close(self) -> None:
        """
        Closes the Endpoint.
        """
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
