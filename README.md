# IPv8-rust-tunnels
[![](https://img.shields.io/pypi/v/ipv8-rust-tunnels.svg?label=PyPI)](https://pypi.org/project/ipv8-rust-tunnels/) &emsp; ![Unit tests](https://github.com/Tribler/ipv8-rust-tunnels/actions/workflows/test.yml/badge.svg)

This module provides a set of performance enhancements to the `TunnelCommunity`, the anonymization layer used in [IPv8](https://github.com/Tribler/py-ipv8) and [Tribler](https://github.com/Tribler/tribler). It works by handling the tunnel data traffic in Rust, while letting the Python anonymization layer handle the tunnel control logic.
