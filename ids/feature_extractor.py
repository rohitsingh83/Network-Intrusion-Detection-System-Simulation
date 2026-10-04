"""Validate synthetic flow records and derive analysis-ready network features.

This module never opens sockets, captures packets, or inspects payloads.
"""

from __future__ import annotations

import ipaddress
import math
from typing import Any, Mapping

SUPPORTED_PROTOCOLS = {"TCP", "UDP", "ICMP"}


def _number(record: Mapping[str, Any], name: str, default: float = 0.0) -> float:
    value = record.get(name, default)
    if value is None or value == "":
        value = default
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a finite number") from exc
    if not math.isfinite(parsed):
        raise ValueError(f"{name} must be a finite number")
    return parsed


def _port(record: Mapping[str, Any], name: str) -> int:
    raw = record.get(name, 0)
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer from 0 to 65535") from exc
    if value < 0 or value > 65535:
        raise ValueError(f"{name} must be an integer from 0 to 65535")
    return value


def _ip(record: Mapping[str, Any], name: str) -> str:
    raw = record.get(name)
    if not raw:
        raise ValueError(f"{name} is required")
    try:
        return str(ipaddress.ip_address(str(raw)))
    except ValueError as exc:
        raise ValueError(f"{name} must be a valid IPv4 or IPv6 address") from exc


def extract_network_features(
    flow: Mapping[str, Any], context: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Return validated flow attributes and derived features.

    Missing numeric counters are safely treated as zero. A zero duration uses a
    1 ms denominator so rates remain finite and conspicuous rather than causing
    division-by-zero errors. Invalid IPs, ports, protocols, and non-finite
    counters are rejected instead of silently normalized.
    """
    context = context or {}
    source_ip = _ip(flow, "source_ip")
    destination_ip = _ip(flow, "destination_ip")
    source_port = _port(flow, "source_port")
    destination_port = _port(flow, "destination_port")

    protocol = str(flow.get("protocol", "TCP")).strip().upper()
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ValueError(f"protocol must be one of {sorted(SUPPORTED_PROTOCOLS)}")

    packet_count = max(0.0, _number(flow, "packet_count", 0.0))
    byte_count = max(0.0, _number(flow, "byte_count", 0.0))
    duration = max(0.0, _number(flow, "duration_seconds", flow.get("duration", 0.0)))
    connection_count = max(0.0, _number(flow, "connection_count", 0.0))
    failed_connection_count = max(0.0, _number(flow, "failed_connection_count", 0.0))
    syn_count = max(0.0, _number(flow, "syn_count", 0.0))
    rst_count = max(0.0, _number(flow, "rst_count", 0.0))

    # A zero-duration record can represent a burst; the epsilon keeps values finite.
    safe_duration = max(duration, 0.001)
    average_packet_size = _number(flow, "average_packet_size", 0.0)
    if average_packet_size <= 0 and packet_count > 0:
        average_packet_size = byte_count / packet_count

    unique_destination_ports = max(
        1,
        int(_number(
            context,
            "unique_destination_ports",
            _number(flow, "unique_destination_ports", 1.0),
        )),
    )
    unique_destination_ips = max(
        1,
        int(_number(
            context,
            "unique_destination_ips",
            _number(flow, "unique_destination_ips", 1.0),
        )),
    )

    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": duration,
        "duration": duration,
        "bytes_per_second": byte_count / safe_duration,
        "packets_per_second": packet_count / safe_duration,
        "average_packet_size": average_packet_size,
        "connection_count": connection_count,
        "failed_connection_count": failed_connection_count,
        "failure_ratio": failed_connection_count / max(connection_count, 1.0),
        "syn_count": syn_count,
        "rst_count": rst_count,
        "syn_ratio": syn_count / max(packet_count, 1.0),
        "unique_destination_ports": unique_destination_ports,
        "unique_destination_ips": unique_destination_ips,
        "connection_rate": connection_count / safe_duration,
        "scenario_type": str(flow.get("scenario_type") or "UNSPECIFIED"),
    }
