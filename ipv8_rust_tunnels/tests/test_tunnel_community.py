import asyncio
import unittest
from unittest.mock import Mock

from ipv8_rust_tunnels.endpoint import RustEndpoint

from ipv8.messaging.anonymization.community import CIRCUIT_TYPE_RP_DOWNLOADER
from ipv8.messaging.anonymization.tunnel import PEER_FLAG_SPEED_TEST
from ipv8.messaging.interfaces.endpoint import EndpointListener
from ipv8.messaging.interfaces.udp.endpoint import UDPv4Address
from ipv8.test.messaging.anonymization.test_community import TestTunnelCommunity
from ipv8.test.messaging.anonymization.test_hiddenservices import TestHiddenServices


def create_node(org, *args, **kwargs):  # noqa: ANN201, ANN002, ANN001, D103
    ipv8 = org(*args, **kwargs)
    ipv8.endpoint = ep = RustEndpoint(0, '127.0.0.1')

    ep.open()
    ep.set_exit_address(("127.0.0.1", 0))
    addr = UDPv4Address(*ep.get_address())

    ipv8.my_peer.addresses[UDPv4Address] = addr
    ipv8.endpoint.wan_address = ipv8.endpoint.lan_address = addr

    overlay = ipv8.overlay
    overlay.my_estimated_wan = overlay.my_estimated_lan = addr
    overlay.endpoint = overlay.crypto_endpoint = overlay.settings.endpoint = ep

    ep.setup_tunnels(overlay, overlay.settings)
    ep.remove_listener(ipv8.overlay)
    ep.add_prefix_listener(ipv8.overlay, overlay.get_prefix())

    # Some unittests use prefixes that we don't want blocked. So, we add a fake EndpointListener.
    mock = Mock()
    mock.__class__ = EndpointListener
    ep.add_prefix_listener(mock, b'\x00' * 22)
    ep.add_prefix_listener(mock, b'\x00\x01' + b'\x00' * 20)

    overlay.circuits = ep.circuits
    overlay.relay_from_to = ep.relays
    overlay.exit_sockets = ep.exit_sockets

    return ipv8


async def set_up(org, self) -> None:  # noqa: ANN001, D103
    org(self)


def replace(old_func, new_func):  # noqa: ANN001, D103, ANN201
    return lambda *args, org=old_func, **kwargs: new_func(org, *args, **kwargs)


async def new_test_test_request(self) -> None:
    """
    Check if sending test-request messages works as expected.
    """
    self.add_node_to_experiment(self.create_node())
    self.settings(1).peer_flags |= {PEER_FLAG_SPEED_TEST}
    await self.introduce_nodes()
    circuit = self.overlay(0).create_circuit(2, exit_flags=[PEER_FLAG_SPEED_TEST])
    await circuit.ready

    callback = Mock()
    self.overlay(0).endpoint.run_speedtest(circuit.circuit_id, 10, 10, 10, 1, callback)
    await asyncio.sleep(.1)

    callback.assert_called_once()
    self.assertEqual(len(callback.call_args_list), 1)
    msg_stats = list(callback.call_args_list[0].args[0].values())
    self.assertTrue(sum([stat[1] for stat in msg_stats]) > 0)
    self.assertTrue(sum([stat[3] for stat in msg_stats]) > 0)


async def new_test_test_request_e2e(self, *args) -> None:
    """
    Check if sending test-request messages over an e2e circuit works as expected.
    """
    future = asyncio.Future()

    self.overlay(0).join_swarm(self.service, 1, future.set_result, seeding=False)
    self.overlay(2).join_swarm(self.service, 1, future.set_result)
    self.overlay(2).settings.peer_flags.add(PEER_FLAG_SPEED_TEST)

    await self.introduce_nodes()
    await self.create_intro(2, self.service)
    await self.assign_exit_node(0)

    await self.overlay(0).do_peer_discovery()
    await self.deliver_messages()

    await future

    circuit, = self.overlay(0).find_circuits(ctype=CIRCUIT_TYPE_RP_DOWNLOADER)
    callback = Mock()
    self.overlay(0).endpoint.run_speedtest(circuit.circuit_id, 10, 3, 6, 1, callback)
    await asyncio.sleep(.1)

    callback.assert_called_once()
    self.assertEqual(len(callback.call_args_list), 1)
    msg_stats = list(callback.call_args_list[0].args[0].values())
    self.assertTrue(sum([stat[1] for stat in msg_stats]) > 0)
    self.assertTrue(sum([stat[3] for stat in msg_stats]) > 0)


TestTunnelCommunity.create_node = replace(TestTunnelCommunity.create_node, create_node)
TestTunnelCommunity.setUp = replace(TestTunnelCommunity.setUp, set_up)
TestTunnelCommunity.test_test_request = new_test_test_request
TestTunnelCommunity.test_tunnel_unicode_destination = \
    unittest.skip("not available in RustEndpoint")(TestTunnelCommunity.test_tunnel_unicode_destination)

TestHiddenServices.create_node = replace(TestHiddenServices.create_node, create_node)
TestHiddenServices.setUp = replace(TestHiddenServices.setUp, set_up)
TestHiddenServices.test_test_request_e2e = new_test_test_request_e2e
TestHiddenServices.test_dht_lookup_with_counterparty = \
    unittest.skip("not available in RustEndpoint")(TestHiddenServices.test_dht_lookup_with_counterparty)

if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(unittest.makeSuite(TestTunnelCommunity))
    runner.run(unittest.makeSuite(TestHiddenServices))
