"""Explainable, configurable signature-style rules for synthetic flow records."""

from __future__ import annotations

from typing import Any, Mapping

from ids.config import DEFAULT_RULES


def _rules_by_id(configured_rules: Mapping[str, Mapping[str, Any]] | None) -> dict[str, dict[str, Any]]:
    if configured_rules is None:
        return {rule["rule_id"]: rule for rule in DEFAULT_RULES}
    result: dict[str, dict[str, Any]] = {}
    for rule in DEFAULT_RULES:
        override = configured_rules.get(rule["rule_id"], {})
        merged = {**rule, **dict(override)}
        if "config" not in merged:
            merged["config"] = rule.get("config", {})
        result[rule["rule_id"]] = merged
    return result


def analyze_flow(
    features: Mapping[str, Any],
    configured_rules: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return all matching rules, including evidence and the active threshold.

    A match is an investigation signal, not proof of malicious activity.
    """
    rules = _rules_by_id(configured_rules)
    matches: list[dict[str, Any]] = []

    def add(rule_id: str, evidence: str) -> None:
        rule = rules[rule_id]
        if not bool(rule.get("enabled", True)):
            return
        matches.append({
            "rule_id": rule_id,
            "name": rule["rule_name"],
            "severity": rule["severity"],
            "description": rule["description"],
            "threshold": rule.get("threshold"),
            "evidence": evidence,
        })

    rule = rules["IDS-001"]
    threshold = float(rule.get("threshold", 12.0))
    if bool(rule.get("enabled", True)) and float(features.get("connection_rate", 0)) >= threshold:
        add("IDS-001", f"{float(features['connection_rate']):.2f} connections/s >= {threshold:.2f}")

    rule = rules["IDS-002"]
    threshold = float(rule.get("threshold", 5.0))
    min_ratio = float(rule.get("config", {}).get("minimum_failure_ratio", 0.45))
    failures = float(features.get("failed_connection_count", 0))
    failure_ratio = float(features.get("failure_ratio", 0))
    if bool(rule.get("enabled", True)) and failures >= threshold and failure_ratio >= min_ratio:
        add("IDS-002", f"{failures:.0f} failures; ratio {failure_ratio:.2f} >= {min_ratio:.2f}")

    rule = rules["IDS-003"]
    threshold = float(rule.get("threshold", 12.0))
    unique_ports = float(features.get("unique_destination_ports", 1))
    if bool(rule.get("enabled", True)) and unique_ports >= threshold:
        add("IDS-003", f"{unique_ports:.0f} unique destination ports >= {threshold:.0f}")

    rule = rules["IDS-004"]
    threshold = float(rule.get("threshold", 15.0))
    min_syn_ratio = float(rule.get("config", {}).get("minimum_syn_ratio", 0.70))
    syn_count = float(features.get("syn_count", 0))
    syn_ratio = float(features.get("syn_ratio", 0))
    if bool(rule.get("enabled", True)) and syn_count >= threshold and syn_ratio >= min_syn_ratio:
        add("IDS-004", f"{syn_count:.0f} SYNs; SYN/packet ratio {syn_ratio:.2f} >= {min_syn_ratio:.2f}")

    rule = rules["IDS-005"]
    ports = {int(port) for port in rule.get("config", {}).get("ports", [22, 3389, 3306, 5432, 445])}
    destination_port = int(features.get("destination_port", 0))
    protocol = str(features.get("protocol", "TCP")).upper()
    if bool(rule.get("enabled", True)) and destination_port in ports and protocol != "TCP":
        add("IDS-005", f"UDP/ICMP observed on TCP-oriented service port {destination_port}")

    rule = rules["IDS-006"]
    byte_threshold = float(rule.get("threshold", 2_000_000.0))
    rate_threshold = float(rule.get("config", {}).get("bytes_per_second_threshold", 5_000_000.0))
    byte_count = float(features.get("byte_count", 0))
    byte_rate = float(features.get("bytes_per_second", 0))
    if bool(rule.get("enabled", True)) and (byte_count >= byte_threshold or byte_rate >= rate_threshold):
        add("IDS-006", f"{byte_count:.0f} bytes or {byte_rate:.0f} bytes/s crossed configured volume limits")

    return matches
