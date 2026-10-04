"""Create evidence-rich analyst alerts from hybrid IDS evaluations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import uuid4

from ids.config import ALERT_THRESHOLD, SEVERITY_ORDER
from ids.risk_engine import severity_for_risk


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def generate_alert(
    flow: Mapping[str, Any],
    evaluation: Mapping[str, Any],
    alert_id: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any] | None:
    """Return an alert when a rule matches or risk reaches the project threshold."""
    matches = list(evaluation.get("matched_rules", []))
    risk_score = int(evaluation.get("risk_score", 0))
    if not matches and risk_score < ALERT_THRESHOLD:
        return None

    primary = sorted(
        matches,
        key=lambda item: SEVERITY_ORDER.get(str(item.get("severity", "LOW")).upper(), 1),
        reverse=True,
    )[0] if matches else None
    alert_type = primary.get("name") if primary else "Statistical Anomaly"
    rule_id = primary.get("rule_id") if primary else "ANOMALY-001"
    reasons = [item.get("evidence", item.get("description", "Rule match")) for item in matches]
    if not reasons:
        reasons.append(
            f"Anomaly score {evaluation.get('anomaly_score', 0)}/100 crossed the investigation threshold."
        )
    reasons.append("Synthetic detection evidence requires analyst triage; it is not proof of compromise.")

    return {
        "alert_id": alert_id or f"ALT-{uuid4().hex[:8].upper()}",
        "timestamp": timestamp or utc_now_iso(),
        "source_ip": str(flow.get("source_ip", "")),
        "destination_ip": str(flow.get("destination_ip", "")),
        "protocol": str(flow.get("protocol", "TCP")).upper(),
        "source_port": int(flow.get("source_port", 0)),
        "destination_port": int(flow.get("destination_port", 0)),
        "flow_id": str(flow.get("flow_id", "")),
        "rule_id": rule_id,
        "alert_type": alert_type,
        "severity": severity_for_risk(risk_score),
        "risk_score": risk_score,
        "anomaly_score": int(evaluation.get("anomaly_score", 0)),
        "ml_probability": evaluation.get("ml_probability"),
        "description": " ".join(reasons),
        "matched_rules": matches,
        "status": "NEW",
        "occurrence_count": 1,
        "last_seen": timestamp or utc_now_iso(),
    }
