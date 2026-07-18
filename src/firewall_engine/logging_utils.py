from __future__ import annotations

import json
from pathlib import Path

from firewall_engine.engine import Decision
from firewall_engine.models import Packet


def create_event(
    packet: Packet,
    decision: Decision,
) -> dict[str, object]:
    """Convert a packet decision into a structured event."""

    return {
        "timestamp": packet.timestamp.isoformat(),
        "source": {
            "ip": packet.src_ip,
            "port": packet.src_port,
        },
        "destination": {
            "ip": packet.dst_ip,
            "port": packet.dst_port,
        },
        "protocol": packet.protocol,
        "action": decision.action,
        "rule_name": decision.rule_name,
        "reason": decision.reason,
        "five_tuple": list(packet.five_tuple),
    }


def write_event(
    packet: Packet,
    decision: Decision,
    log_path: str | Path = "logs/firewall-events.jsonl",
) -> None:
    """Append one firewall event to a JSON Lines log file."""

    output_path = Path(log_path)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    event = create_event(
        packet,
        decision,
    )

    with output_path.open(
        "a",
        encoding="utf-8",
    ) as log_file:
        log_file.write(
            json.dumps(event) + "\n"
        )
