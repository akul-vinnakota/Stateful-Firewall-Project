from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address


SUPPORTED_PROTOCOLS = {"TCP", "UDP", "ICMP"}


@dataclass(frozen=True, slots=True)
class Packet:
    """Represents a network packet evaluated by the firewall engine."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload: bytes = b""
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        validated_src_ip = str(ip_address(self.src_ip))
        validated_dst_ip = str(ip_address(self.dst_ip))
        normalized_protocol = self.protocol.upper()

        if normalized_protocol not in SUPPORTED_PROTOCOLS:
            raise ValueError(
                f"Unsupported protocol: {self.protocol}. "
                f"Supported protocols: {sorted(SUPPORTED_PROTOCOLS)}"
            )

        self._validate_port("src_port", self.src_port)
        self._validate_port("dst_port", self.dst_port)

        if not isinstance(self.payload, bytes):
            raise TypeError("payload must be stored as bytes")

        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must include timezone information")

        object.__setattr__(self, "src_ip", validated_src_ip)
        object.__setattr__(self, "dst_ip", validated_dst_ip)
        object.__setattr__(self, "protocol", normalized_protocol)

    @staticmethod
    def _validate_port(field_name: str, port: int) -> None:
        if not isinstance(port, int):
            raise TypeError(f"{field_name} must be an integer")

        if not 0 <= port <= 65535:
            raise ValueError(
                f"{field_name} must be between 0 and 65535"
            )

    @property
    def five_tuple(self) -> tuple[str, str, int, int, str]:
        """Return the packet's five-tuple flow identifier."""

        return (
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
            self.protocol,
        )