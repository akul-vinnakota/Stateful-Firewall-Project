from __future__ import annotations

from dataclasses import dataclass

from firewall_engine.models import Packet
from firewall_engine.rules import Rule, SUPPORTED_ACTIONS


@dataclass(frozen=True, slots=True)
class Decision:
    """Represents the firewall decision for one packet."""

    action: str
    rule_name: str
    reason: str


class FirewallEngine:
    """Evaluate packets against an ordered stateless ruleset."""

    def __init__(
        self,
        rules: list[Rule],
        default_action: str = "block",
    ) -> None:
        normalized_default = default_action.lower()

        if normalized_default not in SUPPORTED_ACTIONS:
            raise ValueError(
                "default_action must be 'allow' or 'block'"
            )

        self.rules = rules
        self.default_action = normalized_default

    def evaluate(self, packet: Packet) -> Decision:
        """Apply first-match-wins rule processing."""

        for rule in self.rules:
            if rule.matches(packet):
                return Decision(
                    action=rule.action,
                    rule_name=rule.name,
                    reason=rule.reason,
                )

        return Decision(
            action=self.default_action,
            rule_name="default-policy",
            reason=(
                "No explicit rule matched; "
                f"default policy is {self.default_action}"
            ),
        )
