from __future__ import annotations

import random

from firewall_engine.models import Packet


class TrafficSimulator:
    """Generate repeatable simulated network traffic."""

    def __init__(self, seed: int | None = None) -> None:
        self.random = random.Random(seed)

    def generate_packet(self) -> Packet:
        protocol = self.random.choice(
            ["TCP", "TCP", "TCP", "UDP", "UDP", "ICMP"]
        )

        src_ip = self.random.choice(
            [
                self._random_host("192.168.1"),
                self._random_host("172.16.0"),
                self._random_host("10.1.0"),
            ]
        )

        dst_ip = self._random_host("10.0.0")

        if protocol == "TCP":
            src_port = self.random.randint(1024, 65535)
            dst_port = self.random.choice(
                [23, 80, 443, 445, 3389, 8080]
            )
            payload = b"simulated-tcp-payload"

        elif protocol == "UDP":
            src_port = self.random.randint(1024, 65535)
            dst_port = self.random.choice(
                [53, 123, 161, 9999]
            )
            payload = b"simulated-udp-payload"

        else:
            src_port = 0
            dst_port = 0
            payload = b"simulated-icmp-payload"

        return Packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            payload=payload,
        )

    def generate_packets(self, count: int) -> list[Packet]:
        if not isinstance(count, int):
            raise TypeError("count must be an integer")

        if count < 1:
            raise ValueError("count must be at least 1")

        return [
            self.generate_packet()
            for _ in range(count)
        ]

    def _random_host(self, network_prefix: str) -> str:
        host = self.random.randint(1, 254)
        return f"{network_prefix}.{host}"
