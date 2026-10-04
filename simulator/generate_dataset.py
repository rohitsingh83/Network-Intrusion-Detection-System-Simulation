"""Generate a reproducible, balanced-enough synthetic network-flow CSV."""

from __future__ import annotations

import argparse
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from simulator.scenarios import NORMAL_SCENARIOS, SUSPICIOUS_SCENARIOS, make_synthetic_flow, timestamp_at

DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "data" / "network_traffic.csv"
FIELDNAMES = [
    "flow_id", "timestamp", "source_ip", "destination_ip", "source_port",
    "destination_port", "protocol", "packet_count", "byte_count", "duration_seconds",
    "connection_count", "failed_connection_count", "syn_count", "rst_count",
    "average_packet_size", "unique_destination_ports", "unique_destination_ips",
    "label", "scenario_type",
]


def generate_records(count: int = 5_000, seed: int = 42) -> list[dict]:
    if count < 0:
        raise ValueError("count must be zero or greater")
    rng = random.Random(seed)
    normal_count = round(count * 0.75)
    scenarios = [rng.choice(NORMAL_SCENARIOS) for _ in range(normal_count)]
    scenarios.extend(rng.choice(SUSPICIOUS_SCENARIOS) for _ in range(count - normal_count))
    rng.shuffle(scenarios)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = now - timedelta(hours=24)
    records = []
    for index, scenario in enumerate(scenarios, start=1):
        record = make_synthetic_flow(
            scenario,
            flow_id=f"DATA-{index:07d}",
            timestamp=timestamp_at(start, index - 1, count),
            rng=rng,
        )
        records.append(record)
    return records


def save_dataset(output: str | Path = DEFAULT_OUTPUT, count: int = 5_000, seed: int = 42) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    records = generate_records(count=count, seed=seed)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(records)
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="Create synthetic flow records; no packets are sent.")
    parser.add_argument("--count", type=int, default=5_000, help="number of rows (default: 5000)")
    parser.add_argument("--seed", type=int, default=42, help="reproducible random seed")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="CSV destination")
    args = parser.parse_args()
    output = save_dataset(args.output, args.count, args.seed)
    print(f"Wrote {args.count:,} synthetic flow records to {output}")
    print("All source/destination IPs use RFC 5737 documentation ranges; no traffic was emitted.")


if __name__ == "__main__":
    main()
