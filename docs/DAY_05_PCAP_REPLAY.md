# Day 5: Offline PCAP Replay

## Objective

Add safe offline packet-capture replay using Scapy.

## Features

- Read packets from PCAP files
- Parse IPv4 TCP, UDP, and ICMP traffic
- Convert captured packets into the validated firewall Packet model
- Preserve transport ports and raw payload bytes
- Ignore unsupported packet types
- Process captured traffic through the existing rules engine
- Produce structured JSON event logs and summary statistics

## Create the demonstration capture

Run:

    PYTHONPATH=src python scripts/create_demo_pcap.py

This creates:

    captures/demo-traffic.pcap

## Replay the capture

Run:

    PYTHONPATH=src python main.py --pcap captures/demo-traffic.pcap --log logs/pcap-replay-events.jsonl

## Security engineering value

Offline PCAP replay makes testing safe and repeatable. The same captured traffic can be evaluated after rule changes, logging changes, or future stateful connection-tracking changes.

## Current limitations

- Only IPv4 TCP, UDP, and ICMP packets are currently supported.
- ARP, IPv6, and other protocols are skipped.
- Replay evaluates packets offline and does not block live traffic.
- Connection state is not tracked yet.
