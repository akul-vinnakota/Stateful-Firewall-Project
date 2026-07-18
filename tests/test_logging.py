import json

from firewall_engine.engine import Decision
from firewall_engine.logging_utils import create_event, write_event
from firewall_engine.models import Packet


def make_packet() -> Packet:
    return Packet(
        src_ip="192.168.1.25",
        dst_ip="10.0.0.10",
        src_port=51500,
        dst_port=443,
        protocol="TCP",
        payload=b"test-data",
    )


def make_decision() -> Decision:
    return Decision(
        action="allow",
        rule_name="allow-internal-https",
        reason="Authorized internal HTTPS traffic",
    )


def test_create_event_contains_packet_metadata() -> None:
    event = create_event(
        make_packet(),
        make_decision(),
    )

    assert event["source"] == {
        "ip": "192.168.1.25",
        "port": 51500,
    }

    assert event["destination"] == {
        "ip": "10.0.0.10",
        "port": 443,
    }

    assert event["protocol"] == "TCP"
    assert event["action"] == "allow"
    assert event["rule_name"] == "allow-internal-https"


def test_create_event_contains_timestamp_and_five_tuple() -> None:
    event = create_event(
        make_packet(),
        make_decision(),
    )

    assert isinstance(event["timestamp"], str)

    assert event["five_tuple"] == [
        "192.168.1.25",
        "10.0.0.10",
        51500,
        443,
        "TCP",
    ]


def test_write_event_creates_json_lines_file(tmp_path) -> None:
    log_path = tmp_path / "firewall-events.jsonl"

    write_event(
        make_packet(),
        make_decision(),
        log_path,
    )

    lines = log_path.read_text(
        encoding="utf-8",
    ).splitlines()

    assert len(lines) == 1

    event = json.loads(lines[0])

    assert event["action"] == "allow"
    assert event["rule_name"] == "allow-internal-https"


def test_write_event_appends_multiple_events(tmp_path) -> None:
    log_path = tmp_path / "firewall-events.jsonl"

    write_event(
        make_packet(),
        make_decision(),
        log_path,
    )

    write_event(
        make_packet(),
        make_decision(),
        log_path,
    )

    lines = log_path.read_text(
        encoding="utf-8",
    ).splitlines()

    assert len(lines) == 2
