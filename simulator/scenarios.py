"""Create safe synthetic flow *records* using RFC 5737 documentation IP ranges.

Nothing here sends packets, opens sockets, scans hosts, or performs an attack.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from ids.timeutils import normalize_timestamp

NORMAL_SCENARIOS = [
    "NORMAL_WEB",
    "NORMAL_DNS",
    "NORMAL_SSH",
    "NORMAL_EMAIL",
    "NORMAL_DATABASE",
]
SUSPICIOUS_SCENARIOS = [
    "HIGH_CONNECTION_RATE",
    "REPEATED_FAILED_CONNECTIONS",
    "MULTI_PORT_PROBING_PATTERN",
    "SYN_HEAVY_PATTERN",
    "UNUSUAL_PORT_ACTIVITY",
    "HIGH_TRAFFIC_VOLUME",
]
ALL_SCENARIOS = NORMAL_SCENARIOS + SUSPICIOUS_SCENARIOS

SOURCE_IPS = [f"192.0.2.{last}" for last in range(10, 211)]
DESTINATION_IPS = [f"198.51.100.{last}" for last in range(10, 211)] + [
    f"203.0.113.{last}" for last in range(10, 211)
]


def _base_record(
    rng: random.Random,
    flow_id: str | None,
    scenario_type: str,
    timestamp: str | None,
    source_ip: str | None,
) -> dict[str, Any]:
    source = source_ip or rng.choice(SOURCE_IPS)
    destination = rng.choice([ip for ip in DESTINATION_IPS if ip != source])
    return {
        "flow_id": flow_id or f"SIM-{uuid4().hex[:12].upper()}",
        "timestamp": normalize_timestamp(timestamp),
        "source_ip": source,
        "destination_ip": destination,
        "source_port": rng.randint(49152, 65535),
        "destination_port": 443,
        "protocol": "TCP",
        "packet_count": 0,
        "byte_count": 0,
        "duration_seconds": 0.0,
        "connection_count": 1,
        "failed_connection_count": 0,
        "syn_count": 0,
        "rst_count": 0,
        "average_packet_size": 0.0,
        "unique_destination_ports": 1,
        "unique_destination_ips": 1,
        "label": "NORMAL" if scenario_type in NORMAL_SCENARIOS else "SUSPICIOUS",
        "scenario_type": scenario_type,
    }


def make_synthetic_flow(
    scenario_type: str | None = None,
    *,
    flow_id: str | None = None,
    timestamp: str | None = None,
    source_ip: str | None = None,
    rng: random.Random | None = None,
) -> dict[str, Any]:
    """Build one flow-like JSON record; no network traffic is emitted."""
    rng = rng or random.Random()
    scenario_type = scenario_type or rng.choice(ALL_SCENARIOS)
    if scenario_type not in ALL_SCENARIOS:
        raise ValueError(f"Unsupported scenario_type: {scenario_type}")
    flow = _base_record(rng, flow_id, scenario_type, timestamp, source_ip)

    if scenario_type == "NORMAL_WEB":
        flow.update(protocol="TCP", destination_port=rng.choice([80, 443]),
                    packet_count=rng.randint(12, 180), byte_count=rng.randint(1_000, 180_000),
                    duration_seconds=round(rng.uniform(0.7, 45.0), 3),
                    connection_count=rng.randint(1, 4), syn_count=rng.randint(1, 4),
                    rst_count=rng.randint(0, 1))
    elif scenario_type == "NORMAL_DNS":
        flow.update(protocol="UDP", destination_port=53,
                    packet_count=rng.randint(2, 18), byte_count=rng.randint(100, 1_800),
                    duration_seconds=round(rng.uniform(0.25, 2.5), 3),
                    connection_count=rng.randint(1, 2), syn_count=0, rst_count=0)
    elif scenario_type == "NORMAL_SSH":
        flow.update(protocol="TCP", destination_port=22,
                    packet_count=rng.randint(8, 90), byte_count=rng.randint(500, 35_000),
                    duration_seconds=round(rng.uniform(10.0, 300.0), 3),
                    connection_count=rng.randint(1, 2), failed_connection_count=0,
                    syn_count=rng.randint(1, 2), rst_count=0)
    elif scenario_type == "NORMAL_EMAIL":
        flow.update(protocol="TCP", destination_port=rng.choice([25, 465, 587]),
                    packet_count=rng.randint(20, 260), byte_count=rng.randint(2_000, 350_000),
                    duration_seconds=round(rng.uniform(1.0, 90.0), 3),
                    connection_count=rng.randint(1, 3), syn_count=rng.randint(1, 3), rst_count=0)
    elif scenario_type == "NORMAL_DATABASE":
        flow.update(protocol="TCP", destination_port=rng.choice([3306, 5432]),
                    packet_count=rng.randint(25, 500), byte_count=rng.randint(4_000, 450_000),
                    duration_seconds=round(rng.uniform(0.5, 120.0), 3),
                    connection_count=rng.randint(1, 5), syn_count=rng.randint(1, 5), rst_count=0)
    elif scenario_type == "HIGH_CONNECTION_RATE":
        flow.update(protocol="TCP", destination_port=443,
                    packet_count=rng.randint(90, 300), byte_count=rng.randint(15_000, 90_000),
                    duration_seconds=round(rng.uniform(1.0, 4.0), 3),
                    connection_count=rng.randint(45, 100), syn_count=rng.randint(35, 90),
                    rst_count=rng.randint(2, 12))
    elif scenario_type == "REPEATED_FAILED_CONNECTIONS":
        count = rng.randint(9, 28)
        flow.update(protocol="TCP", destination_port=22,
                    packet_count=rng.randint(40, 160), byte_count=rng.randint(4_000, 24_000),
                    duration_seconds=round(rng.uniform(25.0, 180.0), 3),
                    connection_count=count, failed_connection_count=rng.randint(max(6, count - 3), count),
                    syn_count=count, rst_count=rng.randint(5, count))
    elif scenario_type == "MULTI_PORT_PROBING_PATTERN":
        count = rng.randint(15, 48)
        flow.update(protocol="TCP", destination_port=rng.randint(1, 65535),
                    packet_count=rng.randint(30, 180), byte_count=rng.randint(2_000, 35_000),
                    duration_seconds=round(rng.uniform(4.0, 35.0), 3),
                    connection_count=count, failed_connection_count=rng.randint(4, count),
                    syn_count=rng.randint(12, 50), rst_count=rng.randint(4, 35),
                    unique_destination_ports=rng.randint(15, 42))
    elif scenario_type == "SYN_HEAVY_PATTERN":
        packets = rng.randint(35, 120)
        flow.update(protocol="TCP", destination_port=443,
                    packet_count=packets, byte_count=rng.randint(3_000, 25_000),
                    duration_seconds=round(rng.uniform(2.0, 18.0), 3),
                    connection_count=rng.randint(18, 50), failed_connection_count=rng.randint(5, 22),
                    syn_count=rng.randint(int(packets * 0.76), packets),
                    rst_count=rng.randint(5, 45))
    elif scenario_type == "UNUSUAL_PORT_ACTIVITY":
        flow.update(protocol="UDP", destination_port=rng.choice([22, 3389, 3306, 5432, 445]),
                    packet_count=rng.randint(8, 90), byte_count=rng.randint(500, 45_000),
                    duration_seconds=round(rng.uniform(0.5, 20.0), 3),
                    connection_count=rng.randint(1, 7), failed_connection_count=rng.randint(0, 2),
                    syn_count=0, rst_count=0)
    elif scenario_type == "HIGH_TRAFFIC_VOLUME":
        flow.update(protocol=rng.choice(["TCP", "UDP"]), destination_port=rng.choice([443, 53, 8443]),
                    packet_count=rng.randint(4_000, 18_000), byte_count=rng.randint(2_200_000, 12_000_000),
                    duration_seconds=round(rng.uniform(12.0, 90.0), 3),
                    connection_count=rng.randint(5, 30), syn_count=rng.randint(2, 20),
                    rst_count=rng.randint(0, 4))

    if flow["packet_count"] > 0:
        flow["average_packet_size"] = round(flow["byte_count"] / flow["packet_count"], 3)
    return flow


def choose_scenario(mode: str, index: int, rng: random.Random) -> str:
    """Select deterministic-enough scenarios for a live replay."""
    if mode == "normal":
        return rng.choice(NORMAL_SCENARIOS)
    if mode != "mixed":
        raise ValueError("mode must be 'normal' or 'mixed'")
    # Every sixth event is intentionally synthetic/suspicious so a short demo is visible.
    if index % 6 == 5:
        return rng.choice(SUSPICIOUS_SCENARIOS)
    return rng.choice(NORMAL_SCENARIOS)


def timestamp_at(start: datetime, index: int, total: int) -> str:
    if total <= 1:
        when = start
    else:
        when = start + timedelta(seconds=(24 * 60 * 60) * index / (total - 1))
    return when.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
