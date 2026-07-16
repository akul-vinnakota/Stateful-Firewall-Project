from __future__ import annotations

import json
from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from pathlib import Path

from firewall_engine.models import Packet, SUPPORTED_PROTOCOLS


Network = IPv4Network | IPv6Network
SUPPORTED_ACTIONS = {"allow", "block"}


@dataclass(frozen=True, slots=True)
class Rule:
    """Represents one ordered firewall policy rule."""

    name: str
    action: str
    reason: str
    src_cidr: str | None = None
    dst_cidr: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None

    _src_network: Network | None = field(
        init=False,
        repr=False,
        compare=False,
        default=None,
    )

    _dst_network: Network | None = field(
        init=False,
        repr=False,
        compare=False,
        default=None,
    )

    def __post_init__(self) -> None:
        normalized_action = self.action.lower()

        if normalized_action not in SUPPORTED_ACTIONS:
            raise ValueError(
                f"Unsupported rule action: {self.action}"
            )

        object.__setattr__(
            self,
            "action",
            normalized_action,
        )

        if self.protocol is not None:
            normalized_protocol = self.protocol.upper()

            if normalized_protocol not in SUPPORTED_PROTOCOLS:
                raise ValueError(
                    f"Unsupported rule protocol: {self.protocol}"
                )

            object.__setattr__(
                self,
                "protocol",
                normalized_protocol,
            )

        self._validate_optional_port(
            "src_port",
            self.src_port,
        )

        self._validate_optional_port(
            "dst_port",
            self.dst_port,
        )

        if self.src_cidr is not None:
            object.__setattr__(
                self,
                "_src_network",
                ip_network(
                    self.src_cidr,
                    strict=False,
                ),
            )

        if self.dst_cidr is not None:
            object.__setattr__(
                self,
                "_dst_network",
                ip_network(
                    self.dst_cidr,
                    strict=False,
                ),
            )

    @staticmethod
    def _validate_optional_port(
        field_name: str,
        port: int | None,
    ) -> None:
        if port is None:
            return

        if not isinstance(port, int):
            raise TypeError(
                f"{field_name} must be an integer"
            )

        if not 0 <= port <= 65535:
            raise ValueError(
                f"{field_name} must be between 0 and 65535"
            )

    def matches(self, packet: Packet) -> bool:
        """Return True when every configured condition matches."""

        if (
            self._src_network is not None
            and ip_address(packet.src_ip) not in self._src_network
        ):
            return False

        if (
            self._dst_network is not None
            and ip_address(packet.dst_ip) not in self._dst_network
        ):
            return False

        if (
            self.src_port is not None
            and packet.src_port != self.src_port
        ):
            return False

        if (
            self.dst_port is not None
            and packet.dst_port != self.dst_port
        ):
            return False

        if (
            self.protocol is not None
            and packet.protocol != self.protocol
        ):
            return False

        return True


def load_rules(
    path: str | Path,
) -> tuple[list[Rule], str]:
    """Load firewall rules and default policy from JSON."""

    rules_path = Path(path)

    try:
        data = json.loads(
            rules_path.read_text(encoding="utf-8")
        )
    except FileNotFoundError as exc:
        raise ValueError(
            f"Rules file not found: {rules_path}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Rules file contains invalid JSON: {rules_path}"
        ) from exc

    default_action = data.get(
        "default_action",
        "block",
    ).lower()

    if default_action not in SUPPORTED_ACTIONS:
        raise ValueError(
            "default_action must be 'allow' or 'block'"
        )

    rule_data = data.get("rules", [])

    if not isinstance(rule_data, list):
        raise TypeError(
            "rules must be a JSON list"
        )

    rules = [
        Rule(**item)
        for item in rule_data
    ]

    return rules, default_action
