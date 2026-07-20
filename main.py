from __future__ import annotations

import argparse
import json
from collections import Counter

from firewall_engine.engine import FirewallEngine
from firewall_engine.logging_utils import create_event, write_event
from firewall_engine.rules import load_rules
from firewall_engine.simulator import TrafficSimulator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run simulated traffic through the firewall engine."
    )

    parser.add_argument(
        "--count",
        type=int,
        default=20,
        help="Number of simulated packets to generate.",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Optional seed for repeatable traffic generation.",
    )

    parser.add_argument(
        "--rules",
        default="config/rules.json",
        help="Path to the firewall rules JSON file.",
    )

    parser.add_argument(
        "--log",
        default="logs/firewall-events.jsonl",
        help="Path to the JSON Lines event log.",
    )

    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.count < 1:
        raise SystemExit("--count must be at least 1")

    rules, default_action = load_rules(args.rules)

    engine = FirewallEngine(
        rules=rules,
        default_action=default_action,
    )

    simulator = TrafficSimulator(seed=args.seed)
    packets = simulator.generate_packets(args.count)

    action_counts: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    matched_rules: Counter[str] = Counter()

    for packet in packets:
        decision = engine.evaluate(packet)

        action_counts[decision.action] += 1
        protocol_counts[packet.protocol] += 1
        matched_rules[decision.rule_name] += 1

        write_event(
            packet=packet,
            decision=decision,
            log_path=args.log,
        )

        print(
            json.dumps(
                create_event(packet, decision)
            )
        )

    summary = {
        "packets_processed": len(packets),
        "actions": dict(action_counts),
        "protocols": dict(protocol_counts),
        "matched_rules": dict(matched_rules),
        "log_path": args.log,
    }

    print("\n=== Firewall Simulation Summary ===")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
