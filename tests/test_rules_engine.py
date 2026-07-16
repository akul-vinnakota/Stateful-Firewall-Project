import json

import pytest

from firewall_engine.engine import FirewallEngine
from firewall_engine.models import Packet
from firewall_engine.rules import Rule, load_rules


def make_packet(**overrides) -> Packet:
    values = {
        "src_ip": "192.168.1.25",
        "dst_ip": "10.0.0.10",
        "src_port": 51500,
        "dst_port": 443,
        "protocol": "TCP",
    }

    values.update(overrides)
    return Packet(**values)


def test_rule_matches_cidr_port_and_protocol() -> None:
    rule = Rule(
        name="allow-internal-https",
        action="allow",
        reason="Authorized internal HTTPS traffic",
        src_cidr="192.168.1.0/24",
        dst_cidr="10.0.0.0/24",
        dst_port=443,
        protocol="TCP",
    )

    assert rule.matches(make_packet()) is True


def test_rule_does_not_match_outside_source_cidr() -> None:
    rule = Rule(
        name="allow-internal-https",
        action="allow",
        reason="Authorized internal HTTPS traffic",
        src_cidr="192.168.1.0/24",
        dst_port=443,
        protocol="TCP",
    )

    packet = make_packet(src_ip="172.16.0.25")

    assert rule.matches(packet) is False


def test_rule_rejects_invalid_cidr() -> None:
    with pytest.raises(ValueError):
        Rule(
            name="bad-network",
            action="block",
            reason="Invalid test rule",
            src_cidr="192.168.1.999/24",
        )


def test_rule_rejects_invalid_action() -> None:
    with pytest.raises(ValueError):
        Rule(
            name="bad-action",
            action="drop-now",
            reason="Invalid test rule",
        )


def test_first_matching_rule_wins() -> None:
    rules = [
        Rule(
            name="allow-trusted-subnet",
            action="allow",
            reason="Trusted test subnet",
            src_cidr="192.168.1.0/24",
        ),
        Rule(
            name="block-https",
            action="block",
            reason="HTTPS denied",
            dst_port=443,
            protocol="TCP",
        ),
    ]

    engine = FirewallEngine(
        rules=rules,
        default_action="block",
    )

    decision = engine.evaluate(make_packet())

    assert decision.action == "allow"
    assert decision.rule_name == "allow-trusted-subnet"


def test_default_policy_is_used() -> None:
    engine = FirewallEngine(
        rules=[],
        default_action="block",
    )

    decision = engine.evaluate(make_packet())

    assert decision.action == "block"
    assert decision.rule_name == "default-policy"


def test_load_rules_from_json(tmp_path) -> None:
    rules_file = tmp_path / "rules.json"

    rules_file.write_text(
        json.dumps(
            {
                "default_action": "block",
                "rules": [
                    {
                        "name": "allow-dns",
                        "action": "allow",
                        "reason": "DNS is permitted",
                        "dst_port": 53,
                        "protocol": "UDP"
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    loaded_rules, default_action = load_rules(rules_file)

    assert default_action == "block"
    assert len(loaded_rules) == 1
    assert loaded_rules[0].name == "allow-dns"
