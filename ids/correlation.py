"""Time-window correlation for repeated alerts from the same source and type."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping


def correlation_key(source_ip: str, alert_type: str) -> str:
    """Stable human-readable key used for source/type grouping."""
    return f"{source_ip.strip()}::{alert_type.strip().casefold()}"


def alerts_should_correlate(
    first: Mapping[str, Any], second: Mapping[str, Any], window_seconds: int = 60
) -> bool:
    if correlation_key(str(first.get("source_ip", "")), str(first.get("alert_type", ""))) != correlation_key(
        str(second.get("source_ip", "")), str(second.get("alert_type", ""))
    ):
        return False
    try:
        first_time = datetime.fromisoformat(str(first.get("last_seen", first.get("timestamp", "")).replace("Z", "+00:00")))
        second_time = datetime.fromisoformat(str(second.get("timestamp", "").replace("Z", "+00:00")))
    except (ValueError, TypeError):
        return False
    if first_time.tzinfo is None:
        first_time = first_time.replace(tzinfo=timezone.utc)
    if second_time.tzinfo is None:
        second_time = second_time.replace(tzinfo=timezone.utc)
    return abs((second_time - first_time).total_seconds()) <= window_seconds


def correlate_alerts(
    connection,
    alert: Mapping[str, Any],
    window_seconds: int = 60,
) -> dict[str, Any]:
    """Persist a new alert or fold it into an open source/type group.

    `connection` is a configured SQLite connection. Each flow is still stored;
    `alert_occurrences` preserves which flows contributed to the group.
    """
    timestamp = str(alert.get("timestamp") or datetime.now(timezone.utc).isoformat())
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        parsed = datetime.now(timezone.utc)
    cutoff = (parsed - timedelta(seconds=window_seconds)).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    existing = connection.execute(
        """SELECT * FROM alerts
           WHERE source_ip = ? AND alert_type = ? AND last_seen >= ?
             AND status IN ('NEW', 'INVESTIGATING')
           ORDER BY last_seen DESC LIMIT 1""",
        (alert["source_ip"], alert["alert_type"], cutoff),
    ).fetchone()

    if existing:
        alert_id = existing["alert_id"]
        severity_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        existing_severity = str(existing["severity"]).upper()
        incoming_severity = str(alert.get("severity", "LOW")).upper()
        highest_severity = incoming_severity if severity_rank.get(incoming_severity, 0) > severity_rank.get(existing_severity, 0) else existing_severity
        connection.execute(
            """UPDATE alerts
               SET occurrence_count = occurrence_count + 1,
                   risk_score = MAX(risk_score, ?),
                   severity = ?,
                   anomaly_score = MAX(anomaly_score, ?),
                   ml_probability = CASE
                     WHEN ? IS NULL THEN ml_probability
                     WHEN ml_probability IS NULL THEN ?
                     ELSE MAX(ml_probability, ?) END,
                   last_seen = ?, updated_at = ?
               WHERE alert_id = ?""",
            (
                int(alert.get("risk_score", 0)), highest_severity, int(alert.get("anomaly_score", 0)),
                alert.get("ml_probability"), alert.get("ml_probability"), alert.get("ml_probability"),
                timestamp, timestamp, alert_id,
            ),
        )
        connection.execute(
            "INSERT OR IGNORE INTO alert_occurrences(alert_id, flow_id, observed_at) VALUES (?, ?, ?)",
            (alert_id, alert.get("flow_id"), timestamp),
        )
        row = connection.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        result = dict(row)
        result["correlated"] = True
        return result

    connection.execute(
        """INSERT INTO alerts (
             alert_id, flow_id, source_ip, destination_ip, protocol, source_port,
             destination_port, rule_id, alert_type, severity, description,
             risk_score, anomaly_score, ml_probability, status, occurrence_count,
             created_at, last_seen, updated_at, matched_rules_json
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            alert["alert_id"], alert.get("flow_id"), alert["source_ip"], alert["destination_ip"],
            alert["protocol"], int(alert["source_port"]), int(alert["destination_port"]),
            alert["rule_id"], alert["alert_type"], alert["severity"], alert["description"],
            int(alert["risk_score"]), int(alert.get("anomaly_score", 0)), alert.get("ml_probability"),
            alert.get("status", "NEW"), 1, timestamp, timestamp, timestamp,
            json.dumps(alert.get("matched_rules", [])),
        ),
    )
    connection.execute(
        "INSERT OR IGNORE INTO alert_occurrences(alert_id, flow_id, observed_at) VALUES (?, ?, ?)",
        (alert["alert_id"], alert.get("flow_id"), timestamp),
    )
    row = connection.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert["alert_id"],)).fetchone()
    result = dict(row)
    result["correlated"] = False
    return result
