# Day 4: Configurable Traffic Simulator and CLI

## Objective

Replace hard-coded packets with a configurable traffic generator that can produce repeatable TCP, UDP, and ICMP traffic.

## Simulator features

The traffic simulator generates:

- Random private source IP addresses
- Random destination IP addresses
- TCP, UDP, and ICMP packets
- Common destination ports
- Simulated packet payloads
- Repeatable traffic using a random seed

## Command-line options

Run the default simulation:

    PYTHONPATH=src python main.py

Generate 50 packets:

    PYTHONPATH=src python main.py --count 50

Generate repeatable traffic:

    PYTHONPATH=src python main.py --count 50 --seed 42

Use a different rules file:

    PYTHONPATH=src python main.py --rules config/rules.json

Use a different event log:

    PYTHONPATH=src python main.py --log logs/custom-events.jsonl

## Summary metrics

After processing the traffic, the program displays:

- Total packets processed
- Allow and block totals
- Protocol totals
- Matched firewall rule totals
- Event log location

## Security engineering value

Repeatable packet generation allows firewall behavior to be tested consistently.

The seed option makes it possible to recreate the exact same traffic during debugging, testing, demonstrations, and performance comparisons.

## Current limitation

The generated packets are simulated Python objects.

Passive packet capture and PCAP replay will be added in later phases.
