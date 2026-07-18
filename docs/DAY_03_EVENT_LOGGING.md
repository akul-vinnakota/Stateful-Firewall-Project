# Day 3: Structured Firewall Event Logging

## Objective

Add structured security-event logging and automated GitHub Actions testing.

## Event fields

Each firewall event includes:

- UTC timestamp
- Source IP and port
- Destination IP and port
- Protocol
- Firewall action
- Matched rule name
- Decision reason
- Packet five-tuple

## Log format

Events are stored using JSON Lines.

Each line contains one complete JSON event, making the file easier to:

- Search
- Parse
- Stream
- Export to a SIEM
- Process with Python or command-line tools

## Continuous integration

The GitHub Actions workflow runs the complete test suite using Python 3.11, 3.12, and 3.13.

## Current limitation

The log currently records stateless firewall decisions. Stateful session information will be added later.
