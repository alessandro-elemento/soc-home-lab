#!/usr/bin/env python3
"""
analyze_failed_logons.py

A small, standard-library-only Python re-implementation of the brute-force
detection logic documented in:
  incident-reports/windows/failed-logon-detection-splunk.md
  detections/failed-logon-threshold.spl

The Splunk correlation search used in the lab was:

    index=* EventCode=4625 | stats count by ComputerName, host | where count >= 3

This script does the same thing against a CSV export of Windows Event ID 4625
(Failed Logon) records: it counts failed logon attempts per host and flags any
host that meets or exceeds a configurable threshold (default: 3), mirroring
the alert's detection logic outside of Splunk.

It also reports the Logon Type breakdown per flagged host, since Logon Type
2 (Interactive) with a Source Network Address of 127.0.0.1 indicates a local
logon rather than a remote attack, the same distinction used in the
incident report to characterise the detected activity correctly.

Usage:
    python3 analyze_failed_logons.py sample-4625-events.csv
    python3 analyze_failed_logons.py sample-4625-events.csv --threshold 5
"""

import argparse
import csv
from collections import Counter, defaultdict


def load_events(csv_path):
    """Read a CSV export of Event ID 4625 records into a list of dicts."""
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def analyze(events, threshold):
    """
    Count failed logons per ComputerName and return the hosts that meet or
    exceed the given threshold, along with their Logon Type breakdown.
    """
    counts = Counter(event["ComputerName"] for event in events)
    logon_types = defaultdict(Counter)

    for event in events:
        host = event["ComputerName"]
        logon_type = event.get("Logon_Type", "unknown")
        logon_types[host][logon_type] += 1

    flagged = {
        host: count
        for host, count in counts.items()
        if count >= threshold
    }

    return flagged, logon_types


def describe_logon_type(code):
    """Translate the Windows Logon Type code into a human-readable label."""
    return {
        "2": "Interactive (local console logon)",
        "3": "Network (remote logon)",
        "10": "RemoteInteractive (RDP)",
    }.get(code, f"Type {code}")


def main():
    parser = argparse.ArgumentParser(
        description="Flag hosts with repeated failed logons (Event ID 4625)."
    )
    parser.add_argument("csv_path", help="Path to a CSV export of 4625 events")
    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Minimum failed logon count to flag a host (default: 3)",
    )
    args = parser.parse_args()

    events = load_events(args.csv_path)
    flagged, logon_types = analyze(events, args.threshold)

    print(f"Loaded {len(events)} failed logon event(s) from {args.csv_path}\n")

    if not flagged:
        print(f"No hosts met the threshold of {args.threshold} failed logons.")
        return

    print(f"Hosts meeting or exceeding {args.threshold} failed logons:\n")
    for host, count in flagged.items():
        print(f"  {host}: {count} failed logon attempt(s)")
        for logon_type, type_count in logon_types[host].items():
            print(f"      - {type_count}x {describe_logon_type(logon_type)}")
    print()


if __name__ == "__main__":
    main()
