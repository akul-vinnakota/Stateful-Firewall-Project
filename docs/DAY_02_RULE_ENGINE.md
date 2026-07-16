# Day 2: Configurable Firewall Rules Engine

## Objective

Build an ordered stateless packet-filtering engine that evaluates
network packets against configurable security policies.

## Supported rule attributes

- Source CIDR range
- Destination CIDR range
- Source port
- Destination port
- Protocol
- Allow or block action
- Rule name
- Decision reason

## Processing behavior

Rules are processed from top to bottom.

The first matching rule determines the decision.

When no rule matches, the firewall applies the configured
default policy.

## Security design

The current configuration uses a default-deny policy.

This means traffic is blocked unless an explicit rule allows it.

## Current limitation

The engine evaluates each packet independently.

It does not yet remember connection state or determine whether
a packet belongs to an established TCP or UDP flow.
