import json

from firewall_engine.engine import FirewallEngine
from firewall_engine.logging_utils import create_event, write_event
from firewall_engine.models import Packet
from firewall_engine.rules import load_rules


def main() -> None:
    rules, default_action = load_rules("config/rules.json")

    engine = FirewallEngine(
        rules=rules,
        default_action=default_action,
    )

    sample_packets = [
        Packet(
            src_ip="192.168.1.25",
            dst_ip="10.0.0.10",
            src_port=51500,
            dst_port=443,
            protocol="TCP",
        ),
        Packet(
            src_ip="172.16.0.50",
            dst_ip="10.0.0.10",
            src_port=52000,
            dst_port=23,
            protocol="TCP",
        ),
        Packet(
            src_ip="172.16.0.50",
            dst_ip="10.0.0.10",
            src_port=53000,
            dst_port=9999,
            protocol="UDP",
        ),
    ]

    for packet in sample_packets:
        decision = engine.evaluate(packet)

        write_event(
            packet,
            decision,
        )

        print(
            json.dumps(
                create_event(
                    packet,
                    decision,
                )
            )
        )


if __name__ == "__main__":
    main()
