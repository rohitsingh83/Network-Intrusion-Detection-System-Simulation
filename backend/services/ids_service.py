"""Persistence and orchestration services behind the HTTP API."""

from __future__ import annotations

import csv
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from backend.database import connect
from ids.anomaly_detector import AnomalyDetector
from ids.correlation import correlate_alerts
from ids.pipeline import DetectionPipeline
from ids.timeutils import normalize_timestamp, utc_now_iso
from ml.predict import DEFAULT_MODEL_PATH, load_model, predict_probability

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET = ROOT / "data" / "network_traffic.csv"
STATUS_VALUES = {"NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}
STATUS_TRANSITIONS = {
    "NEW": {"INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"},
    "INVESTIGATING": {"NEW", "RESOLVED", "FALSE_POSITIVE"},
    "RESOLVED": {"INVESTIGATING"},
    "FALSE_POSITIVE": {"INVESTIGATING"},
}


class DuplicateFlowError(Exception):
    pass


def _baseline_from_csv(path: Path) -> AnomalyDetector:
    detector = AnomalyDetector()
    if not path.exists():
        return detector
    from ids.feature_extractor import extract_network_features
    rows = []
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                if row.get("label", "NORMAL").upper() == "NORMAL":
                    rows.append(extract_network_features(row))
        if rows:
            detector.fit(rows)
    except (OSError, ValueError, csv.Error):
        # The app still starts with a conservative documented fallback baseline.
        pass
    return detector


class IDSService:
    def __init__(self, db_path: str | Path, dataset_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path)
        self.dataset_path = Path(dataset_path or DEFAULT_DATASET)
        self.model_bundle = None
        if os.getenv("IDS_ENABLE_ML", "false").strip().lower() in {"1", "true", "yes"}:
            model_path = Path(os.getenv("IDS_MODEL_PATH", str(DEFAULT_MODEL_PATH)))
            self.model_bundle = load_model(model_path)
        scorer = None
        if self.model_bundle is not None:
            scorer = lambda features: predict_probability(self.model_bundle, features)
        self.pipeline = DetectionPipeline(
            anomaly_detector=_baseline_from_csv(self.dataset_path),
            ml_scorer=scorer,
        )

    @property
    def ml_enabled(self) -> bool:
        return self.model_bundle is not None

    def _configured_rules(self, connection: sqlite3.Connection) -> dict[str, dict[str, Any]]:
        result = {}
        for row in connection.execute("SELECT * FROM rules"):
            item = dict(row)
            item["enabled"] = bool(item["enabled"])
            item["config"] = json.loads(item.pop("config_json", "{}"))
            result[item["rule_id"]] = item
        return result

    def _context(self, connection: sqlite3.Connection, flow: Mapping[str, Any], timestamp: str) -> dict[str, int]:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        cutoff = (parsed - timedelta(seconds=60)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        rows = connection.execute(
            """SELECT destination_port, destination_ip FROM network_flows
               WHERE source_ip = ? AND timestamp >= ?""",
            (flow["source_ip"], cutoff),
        ).fetchall()
        ports = {int(row["destination_port"]) for row in rows}
        destinations = {str(row["destination_ip"]) for row in rows}
        ports.add(int(flow.get("destination_port", 0)))
        destinations.add(str(flow.get("destination_ip", "")))
        # A simulator/dataset may already carry a pre-aggregated window feature.
        ports_count = max(len(ports), int(flow.get("unique_destination_ports", 1) or 1))
        destinations_count = max(len(destinations), int(flow.get("unique_destination_ips", 1) or 1))
        return {"unique_destination_ports": max(1, ports_count), "unique_destination_ips": max(1, destinations_count)}

    def ingest_flow(self, flow: Mapping[str, Any]) -> dict[str, Any]:
        payload = dict(flow)
        payload["flow_id"] = str(payload.get("flow_id") or f"FLOW-{uuid4().hex[:12].upper()}")
        timestamp = normalize_timestamp(payload.get("timestamp"))
        payload["timestamp"] = timestamp
        created_at = utc_now_iso()
        try:
            with connect(self.db_path) as connection:
                if connection.execute("SELECT 1 FROM network_flows WHERE flow_id = ?", (payload["flow_id"],)).fetchone():
                    raise DuplicateFlowError(f"flow_id '{payload['flow_id']}' already exists")
                context = self._context(connection, payload, timestamp)
                rules = self._configured_rules(connection)
                evaluation = self.pipeline.analyze(payload, context, rules)
                features = evaluation["features"]
                stored_features = {**features, "anomaly_evidence": evaluation["anomaly_evidence"]}
                payload["average_packet_size"] = float(features["average_packet_size"])
                payload["unique_destination_ports"] = int(features["unique_destination_ports"])
                payload["unique_destination_ips"] = int(features["unique_destination_ips"])
                connection.execute(
                    """INSERT INTO network_flows (
                         flow_id, timestamp, source_ip, destination_ip, source_port, destination_port,
                         protocol, packet_count, byte_count, duration_seconds, connection_count,
                         failed_connection_count, syn_count, rst_count, average_packet_size,
                         unique_destination_ports, unique_destination_ips, risk_score, anomaly_score,
                         ml_probability, classification, label, scenario_type, features_json,
                         matched_rules_json, created_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        payload["flow_id"], timestamp, payload["source_ip"], payload["destination_ip"],
                        int(payload.get("source_port", 0)), int(payload.get("destination_port", 0)),
                        str(payload.get("protocol", "TCP")).upper(), float(payload.get("packet_count", 0)),
                        float(payload.get("byte_count", 0)), float(payload.get("duration_seconds", 0)),
                        float(payload.get("connection_count", 1)), float(payload.get("failed_connection_count", 0)),
                        float(payload.get("syn_count", 0)), float(payload.get("rst_count", 0)),
                        float(features["average_packet_size"]), int(features["unique_destination_ports"]),
                        int(features["unique_destination_ips"]), evaluation["risk_score"], evaluation["anomaly_score"],
                        evaluation["ml_probability"], evaluation["classification"], payload.get("label"),
                        payload.get("scenario_type"), json.dumps(stored_features), json.dumps(evaluation["matched_rules"]),
                        created_at,
                    ),
                )
                alert_data = evaluation.get("alert")
                alert_result = None
                if alert_data:
                    alert_data["flow_id"] = payload["flow_id"]
                    alert_result = correlate_alerts(connection, alert_data, window_seconds=60)
                if evaluation["ml_probability"] is not None:
                    connection.execute(
                        "INSERT INTO model_results(flow_id, model_name, prediction, score, created_at) VALUES (?, ?, ?, ?, ?)",
                        (payload["flow_id"], self.model_bundle.get("model_name", "model"),
                         "SUSPICIOUS" if float(evaluation["ml_probability"]) >= 0.5 else "NORMAL",
                         evaluation["ml_probability"], created_at),
                    )
                connection.commit()
        except sqlite3.IntegrityError as exc:
            if "network_flows.flow_id" in str(exc) or "UNIQUE constraint failed" in str(exc):
                raise DuplicateFlowError(f"flow_id '{payload['flow_id']}' already exists") from exc
            raise

        return {
            "flow": self.get_flow(payload["flow_id"]),
            "evaluation": evaluation,
            "alert": alert_result,
        }

    def get_flow(self, flow_id: str) -> dict[str, Any] | None:
        with connect(self.db_path) as connection:
            row = connection.execute("SELECT * FROM network_flows WHERE flow_id = ?", (flow_id,)).fetchone()
            if not row:
                return None
            item = dict(row)
            item["features"] = json.loads(item.pop("features_json", "{}"))
            item["matched_rules"] = json.loads(item.pop("matched_rules_json", "[]"))
            return item

    def list_flows(self, limit: int = 100, search: str | None = None) -> list[dict[str, Any]]:
        clauses = []
        params: list[Any] = []
        if search:
            clauses.append("(source_ip LIKE ? OR destination_ip LIKE ? OR flow_id LIKE ? OR scenario_type LIKE ?)")
            pattern = f"%{search[:120]}%"
            params.extend([pattern] * 4)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with connect(self.db_path) as connection:
            rows = connection.execute(
                f"SELECT * FROM network_flows {where} ORDER BY timestamp DESC LIMIT ?",
                (*params, max(1, min(int(limit), 500))),
            ).fetchall()
            result = []
            for row in rows:
                item = dict(row)
                item["features"] = json.loads(item.pop("features_json", "{}"))
                item.pop("matched_rules_json", None)
                result.append(item)
            return result

    def list_alerts(
        self, severity: str | None = None, protocol: str | None = None,
        alert_type: str | None = None, status: str | None = None,
        hours: int | None = None, limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        if protocol:
            clauses.append("protocol = ?")
            params.append(protocol.upper())
        if alert_type:
            clauses.append("alert_type = ?")
            params.append(alert_type)
        if status:
            clauses.append("status = ?")
            params.append(status.upper())
        if hours is not None:
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=max(0, min(int(hours), 8760)))).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            clauses.append("created_at >= ?")
            params.append(cutoff)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with connect(self.db_path) as connection:
            rows = connection.execute(
                f"SELECT * FROM alerts {where} ORDER BY last_seen DESC LIMIT ?",
                (*params, max(1, min(int(limit), 500))),
            ).fetchall()
            return [self._alert_dict(row) for row in rows]

    @staticmethod
    def _alert_dict(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["matched_rules"] = json.loads(item.pop("matched_rules_json", "[]"))
        return item

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        with connect(self.db_path) as connection:
            row = connection.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            if not row:
                return None
            alert = self._alert_dict(row)
            flow_row = connection.execute("SELECT * FROM network_flows WHERE flow_id = ?", (alert["flow_id"],)).fetchone()
            flow = dict(flow_row) if flow_row else None
            if flow:
                flow["features"] = json.loads(flow.pop("features_json", "{}"))
                flow["matched_rules"] = json.loads(flow.pop("matched_rules_json", "[]"))
            notes = connection.execute("SELECT * FROM incident_notes WHERE alert_id = ? ORDER BY created_at", (alert_id,)).fetchall()
            timeline = connection.execute("SELECT * FROM incident_timeline WHERE alert_id = ? ORDER BY created_at", (alert_id,)).fetchall()
            occurrences = connection.execute(
                """SELECT o.flow_id, o.observed_at, f.destination_ip, f.destination_port, f.protocol
                   FROM alert_occurrences o JOIN network_flows f ON f.flow_id = o.flow_id
                   WHERE o.alert_id = ? ORDER BY o.observed_at""", (alert_id,)
            ).fetchall()
            alert["flow"] = flow
            alert["notes"] = [dict(note) for note in notes]
            alert["timeline"] = [dict(event) for event in timeline]
            alert["occurrences"] = [dict(event) for event in occurrences]
            alert["recommended_steps"] = [
                "Review related flow and alert records in the selected time window.",
                "Check whether the source and destination are known, expected assets.",
                "Compare the behavior with the relevant service and historical baseline.",
                "Review authentication and firewall logs where authorized.",
                "Review endpoint telemetry through approved tools if the asset is in scope.",
                "Document the evidence and disposition; a statistical signal is not proof of compromise.",
            ]
            return alert

    def update_alert_status(
        self, alert_id: str, new_status: str, note: str | None = None,
        resolution_notes: str | None = None, actor: str = "analyst",
    ) -> dict[str, Any] | None:
        new_status = new_status.upper()
        if new_status not in STATUS_VALUES:
            raise ValueError("Invalid alert status")
        timestamp = utc_now_iso()
        with connect(self.db_path) as connection:
            row = connection.execute("SELECT status FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            if row is None:
                return None
            previous = str(row["status"])
            if new_status != previous and new_status not in STATUS_TRANSITIONS.get(previous, set()):
                raise ValueError(f"Status transition {previous} → {new_status} is not allowed")
            started_at = timestamp if new_status == "INVESTIGATING" else None
            resolved_at = timestamp if new_status in {"RESOLVED", "FALSE_POSITIVE"} else None
            connection.execute(
                """UPDATE alerts SET status = ?, updated_at = ?,
                   investigation_started_at = COALESCE(investigation_started_at, ?),
                   resolved_at = ?, resolution_notes = COALESCE(?, resolution_notes)
                   WHERE alert_id = ?""",
                (new_status, timestamp, started_at, resolved_at, resolution_notes, alert_id),
            )
            connection.execute(
                "INSERT INTO incident_timeline(alert_id, from_status, to_status, note, actor, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (alert_id, previous, new_status, note or resolution_notes, actor, timestamp),
            )
            if note:
                connection.execute(
                    "INSERT INTO incident_notes(alert_id, note, author, created_at) VALUES (?, ?, ?, ?)",
                    (alert_id, note, actor, timestamp),
                )
            connection.commit()
        return self.get_alert(alert_id)

    def add_note(self, alert_id: str, note: str, author: str = "analyst") -> dict[str, Any] | None:
        timestamp = utc_now_iso()
        with connect(self.db_path) as connection:
            exists = connection.execute("SELECT 1 FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            if not exists:
                return None
            connection.execute(
                "INSERT INTO incident_notes(alert_id, note, author, created_at) VALUES (?, ?, ?, ?)",
                (alert_id, note.strip(), author.strip(), timestamp),
            )
            connection.execute(
                "INSERT INTO incident_timeline(alert_id, from_status, to_status, note, actor, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (alert_id, None, "NOTE_ADDED", note.strip(), author.strip(), timestamp),
            )
            connection.commit()
        return self.get_alert(alert_id)

    def dashboard_stats(self) -> dict[str, Any]:
        with connect(self.db_path) as connection:
            flow = connection.execute(
                "SELECT COUNT(*) AS total, SUM(CASE WHEN classification = 'NORMAL' THEN 1 ELSE 0 END) AS normal, "
                "SUM(CASE WHEN classification != 'NORMAL' THEN 1 ELSE 0 END) AS suspicious, "
                "COALESCE(AVG(risk_score), 0) AS avg_risk FROM network_flows"
            ).fetchone()
            alerts = connection.execute(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN status IN ('NEW','INVESTIGATING') THEN 1 ELSE 0 END) AS open, "
                "SUM(CASE WHEN severity = 'CRITICAL' AND status IN ('NEW','INVESTIGATING') THEN 1 ELSE 0 END) AS critical "
                "FROM alerts"
            ).fetchone()
            last_alert = connection.execute("SELECT MAX(last_seen) AS value FROM alerts").fetchone()["value"]
            return {
                "total_flows": int(flow["total"] or 0),
                "normal_flows": int(flow["normal"] or 0),
                "suspicious_flows": int(flow["suspicious"] or 0),
                "total_alerts": int(alerts["total"] or 0),
                "open_alerts": int(alerts["open"] or 0),
                "critical_alerts": int(alerts["critical"] or 0),
                "average_risk_score": round(float(flow["avg_risk"] or 0), 1),
                "last_alert_at": last_alert,
            }

    def dashboard_traffic(self, hours: int = 24, bucket_minutes: int | None = None) -> dict[str, Any]:
        hours = max(1, min(int(hours), 720))
        bucket_minutes = bucket_minutes or (60 if hours >= 24 else 10)
        bucket_seconds = bucket_minutes * 60
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        with connect(self.db_path) as connection:
            flows = connection.execute("SELECT * FROM network_flows WHERE timestamp >= ? ORDER BY timestamp", (cutoff,)).fetchall()
            alerts = connection.execute("SELECT severity, alert_type, source_ip, created_at FROM alerts WHERE created_at >= ?", (cutoff,)).fetchall()
        buckets: dict[int, dict[str, float]] = {}
        protocol_counts: dict[str, int] = {}
        port_counts: dict[str, int] = {}
        risk_buckets = {"0–20": 0, "21–40": 0, "41–60": 0, "61–80": 0, "81–100": 0}
        for row in flows:
            try:
                epoch = int(datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")).timestamp())
            except ValueError:
                continue
            key = epoch - epoch % bucket_seconds
            item = buckets.setdefault(key, {"normal": 0, "suspicious": 0, "packets_per_second": 0.0,
                                            "bytes_per_second": 0.0, "connections_per_minute": 0.0,
                                            "failed_connections": 0.0, "risk_score_total": 0.0, "flows": 0})
            item["flows"] += 1
            item["normal" if row["classification"] == "NORMAL" else "suspicious"] += 1
            features = json.loads(row["features_json"] or "{}")
            item["packets_per_second"] += float(features.get("packets_per_second", 0))
            item["bytes_per_second"] += float(features.get("bytes_per_second", 0))
            item["connections_per_minute"] += float(row["connection_count"])
            item["failed_connections"] += float(row["failed_connection_count"])
            item["risk_score_total"] += float(row["risk_score"])
            protocol_counts[row["protocol"]] = protocol_counts.get(row["protocol"], 0) + 1
            port = str(row["destination_port"])
            port_counts[port] = port_counts.get(port, 0) + 1
            score = int(row["risk_score"])
            risk_buckets["0–20" if score <= 20 else "21–40" if score <= 40 else "41–60" if score <= 60 else "61–80" if score <= 80 else "81–100"] += 1
        timeline = []
        for epoch, item in sorted(buckets.items()):
            count = max(1, item["flows"])
            timeline.append({
                "timestamp": datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z"),
                "normal": int(item["normal"]), "suspicious": int(item["suspicious"]),
                "packets_per_second": round(item["packets_per_second"] / count, 2),
                "bytes_per_second": round(item["bytes_per_second"] / count, 2),
                "connections_per_minute": round(item["connections_per_minute"] / max(bucket_minutes, 1), 2),
                "failed_connections": round(item["failed_connections"], 2),
                "average_risk_score": round(item["risk_score_total"] / count, 1),
            })
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        severity_counts = {name: 0 for name in severity_order}
        type_counts: dict[str, int] = {}
        source_counts: dict[str, int] = {}
        alert_time_counts: dict[int, int] = {}
        for alert in alerts:
            severity_counts[alert["severity"]] = severity_counts.get(alert["severity"], 0) + 1
            type_counts[alert["alert_type"]] = type_counts.get(alert["alert_type"], 0) + 1
            source_counts[alert["source_ip"]] = source_counts.get(alert["source_ip"], 0) + 1
            try:
                epoch = int(datetime.fromisoformat(alert["created_at"].replace("Z", "+00:00")).timestamp())
                key = epoch - epoch % bucket_seconds
                alert_time_counts[key] = alert_time_counts.get(key, 0) + 1
            except ValueError:
                pass
        for point in timeline:
            epoch = int(datetime.fromisoformat(point["timestamp"].replace("Z", "+00:00")).timestamp())
            point["alerts"] = alert_time_counts.get(epoch, 0)
        return {
            "hours": hours,
            "bucket_minutes": bucket_minutes,
            "timeline": timeline,
            "protocol_distribution": [{"name": key, "value": value} for key, value in sorted(protocol_counts.items())],
            "port_distribution": [{"name": key, "value": value} for key, value in sorted(port_counts.items(), key=lambda item: item[1], reverse=True)[:8]],
            "risk_distribution": [{"name": key, "value": value} for key, value in risk_buckets.items()],
            "severity_distribution": [{"name": key, "value": severity_counts.get(key, 0)} for key in severity_order],
            "top_alert_types": [{"name": key, "value": value} for key, value in sorted(type_counts.items(), key=lambda item: item[1], reverse=True)[:8]],
            "top_source_ips": [{"name": key, "value": value} for key, value in sorted(source_counts.items(), key=lambda item: item[1], reverse=True)[:8]],
            "flow_rows": len(flows),
        }

    def list_rules(self) -> list[dict[str, Any]]:
        with connect(self.db_path) as connection:
            rows = connection.execute("SELECT * FROM rules ORDER BY rule_id").fetchall()
            result = []
            for row in rows:
                item = dict(row)
                item["enabled"] = bool(item["enabled"])
                item["config"] = json.loads(item.pop("config_json", "{}"))
                result.append(item)
            return result

    def update_rule(self, rule_id: str, enabled: bool | None, threshold: float | None) -> dict[str, Any] | None:
        with connect(self.db_path) as connection:
            row = connection.execute("SELECT * FROM rules WHERE rule_id = ?", (rule_id,)).fetchone()
            if row is None:
                return None
            updated_enabled = int(enabled) if enabled is not None else row["enabled"]
            updated_threshold = float(threshold) if threshold is not None else row["threshold"]
            connection.execute(
                "UPDATE rules SET enabled = ?, threshold = ?, updated_at = ? WHERE rule_id = ?",
                (updated_enabled, updated_threshold, utc_now_iso(), rule_id),
            )
            connection.commit()
        return next((rule for rule in self.list_rules() if rule["rule_id"] == rule_id), None)

    def seed_demo_if_empty(self) -> int:
        """Populate an empty local database with recent synthetic records once."""
        from simulator.scenarios import make_synthetic_flow
        with connect(self.db_path) as connection:
            count = int(connection.execute("SELECT COUNT(*) FROM network_flows").fetchone()[0])
        if count:
            return 0
        scenarios = [
            "NORMAL_WEB", "NORMAL_DNS", "NORMAL_SSH", "NORMAL_DATABASE", "NORMAL_EMAIL",
            "HIGH_CONNECTION_RATE", "REPEATED_FAILED_CONNECTIONS", "MULTI_PORT_PROBING_PATTERN",
            "SYN_HEAVY_PATTERN", "HIGH_TRAFFIC_VOLUME", "UNUSUAL_PORT_ACTIVITY",
        ]
        from random import Random
        rng = Random(17)
        inserted = 0
        for index in range(48):
            scenario = scenarios[index % len(scenarios)]
            # Correlate a few events under one reserved source for the console's demo view.
            source = "192.0.2.77" if scenario in {"MULTI_PORT_PROBING_PATTERN", "HIGH_CONNECTION_RATE"} else None
            flow = make_synthetic_flow(
                scenario, flow_id=f"DEMO-{index + 1:04d}", source_ip=source, rng=rng,
                timestamp=(datetime.now(timezone.utc) - timedelta(minutes=47 - index)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            )
            self.ingest_flow(flow)
            inserted += 1
        return inserted
