import unittest

from ipv8_rust_tunnels.endpoint import RustEndpoint

from ipv8.messaging.interfaces.udp.endpoint import UDPv4Address
from ipv8.test.messaging.anonymization.test_community import TestTunnelCommunity
from ipv8.test.messaging.anonymization.test_hiddenservices import TestHiddenServices


def create_node(org, *args, **kwargs):  # noqa: ANN201, ANN002, ANN001, D103
    ipv8 = org(*args, **kwargs)
    ipv8.endpoint = ep = RustEndpoint(0, '127.0.0.1')

    ep.rust_ep.open(ep.datagram_received, 1)
    ep.rust_ep.set_exit_address("127.0.0.1:0")
    addr = UDPv4Address(*ep.get_address())

    ipv8.my_peer.addresses[UDPv4Address] = addr
    ipv8.endpoint.wan_address = ipv8.endpoint.lan_address = addr

    overlay = ipv8.overlay
    overlay.my_estimated_wan = overlay.my_estimated_lan = addr
    overlay.endpoint = overlay.crypto_endpoint = overlay.settings.endpoint = ep

    ep.setup_tunnels(overlay, overlay.settings)
    ep.remove_listener(ipv8.overlay)
    ep.add_prefix_listener(ipv8.overlay, overlay.get_prefix())

    overlay.circuits = ep.circuits
    overlay.relay_from_to = ep.relays
    overlay.exit_sockets = ep.exit_sockets

    return ipv8


async def set_up(org, self) -> None:  # noqa: ANN001, D103
    org(self)


def replace(old_func, new_func):  # noqa: ANN001, D103, ANN201
    return lambda *args, org=old_func, **kwargs: new_func(org, *args, **kwargs)


TestTunnelCommunity.create_node = replace(TestTunnelCommunity.create_node, create_node)
TestTunnelCommunity.setUp = replace(TestTunnelCommunity.setUp, set_up)
TestTunnelCommunity.test_tunnel_unicode_destination = \
    unittest.skip("not available in RestEndpoint")(TestTunnelCommunity.test_tunnel_unicode_destination)

TestHiddenServices.create_node = replace(TestHiddenServices.create_node, create_node)
TestHiddenServices.setUp = replace(TestHiddenServices.setUp, set_up)


if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(unittest.makeSuite(TestTunnelCommunity))
    runner.run(unittest.makeSuite(TestHiddenServices))
