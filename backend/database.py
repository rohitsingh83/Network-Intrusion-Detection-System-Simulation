"""SQLite schema and connection helpers for the local IDS simulation."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB_PATH = Path(os.getenv("IDS_DB_PATH", str(ROOT / "data" / "ids.db")))


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    path = Path(db_path or DEFAULT_DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def init_db(db_path: str | Path | None = None) -> None:
    from ids.config import DEFAULT_RULES

    schema = """
    CREATE TABLE IF NOT EXISTS network_flows (
        flow_id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        destination_ip TEXT NOT NULL,
        source_port INTEGER NOT NULL,
        destination_port INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        packet_count REAL NOT NULL DEFAULT 0,
        byte_count REAL NOT NULL DEFAULT 0,
        duration_seconds REAL NOT NULL DEFAULT 0,
        connection_count REAL NOT NULL DEFAULT 0,
        failed_connection_count REAL NOT NULL DEFAULT 0,
        syn_count REAL NOT NULL DEFAULT 0,
        rst_count REAL NOT NULL DEFAULT 0,
        average_packet_size REAL NOT NULL DEFAULT 0,
        unique_destination_ports INTEGER NOT NULL DEFAULT 1,
        unique_destination_ips INTEGER NOT NULL DEFAULT 1,
        risk_score INTEGER NOT NULL DEFAULT 0,
        anomaly_score INTEGER NOT NULL DEFAULT 0,
        ml_probability REAL,
        classification TEXT NOT NULL DEFAULT 'NORMAL',
        label TEXT,
        scenario_type TEXT,
        features_json TEXT NOT NULL DEFAULT '{}',
        matched_rules_json TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY,
        flow_id TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        destination_ip TEXT NOT NULL,
        protocol TEXT NOT NULL,
        source_port INTEGER NOT NULL,
        destination_port INTEGER NOT NULL,
        rule_id TEXT NOT NULL,
        alert_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        description TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        anomaly_score INTEGER NOT NULL DEFAULT 0,
        ml_probability REAL,
        status TEXT NOT NULL DEFAULT 'NEW',
        occurrence_count INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        investigation_started_at TEXT,
        resolved_at TEXT,
        resolution_notes TEXT,
        matched_rules_json TEXT NOT NULL DEFAULT '[]',
        FOREIGN KEY(flow_id) REFERENCES network_flows(flow_id)
    );

    CREATE TABLE IF NOT EXISTS alert_occurrences (
        alert_id TEXT NOT NULL,
        flow_id TEXT NOT NULL,
        observed_at TEXT NOT NULL,
        PRIMARY KEY(alert_id, flow_id),
        FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE,
        FOREIGN KEY(flow_id) REFERENCES network_flows(flow_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS rules (
        rule_id TEXT PRIMARY KEY,
        rule_name TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL,
        threshold REAL NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        config_json TEXT NOT NULL DEFAULT '{}',
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS incident_notes (
        note_id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id TEXT NOT NULL,
        note TEXT NOT NULL,
        author TEXT NOT NULL DEFAULT 'analyst',
        created_at TEXT NOT NULL,
        FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS incident_timeline (
        timeline_id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id TEXT NOT NULL,
        from_status TEXT,
        to_status TEXT NOT NULL,
        note TEXT,
        actor TEXT NOT NULL DEFAULT 'analyst',
        created_at TEXT NOT NULL,
        FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS model_results (
        result_id INTEGER PRIMARY KEY AUTOINCREMENT,
        flow_id TEXT NOT NULL,
        model_name TEXT NOT NULL,
        prediction TEXT NOT NULL,
        score REAL NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(flow_id) REFERENCES network_flows(flow_id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON network_flows(timestamp);
    CREATE INDEX IF NOT EXISTS idx_flows_source_time ON network_flows(source_ip, timestamp);
    CREATE INDEX IF NOT EXISTS idx_flows_classification ON network_flows(classification);
    CREATE INDEX IF NOT EXISTS idx_alerts_status_severity ON alerts(status, severity);
    CREATE INDEX IF NOT EXISTS idx_alerts_source_type_time ON alerts(source_ip, alert_type, last_seen);
    CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
    CREATE INDEX IF NOT EXISTS idx_notes_alert_time ON incident_notes(alert_id, created_at);
    """
    with connect(db_path) as connection:
        connection.executescript(schema)
        from ids.timeutils import utc_now_iso
        for rule in DEFAULT_RULES:
            connection.execute(
                """INSERT OR IGNORE INTO rules
                   (rule_id, rule_name, description, severity, threshold, enabled, config_json, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    rule["rule_id"], rule["rule_name"], rule["description"], rule["severity"],
                    float(rule["threshold"]), int(rule["enabled"]), json.dumps(rule.get("config", {})),
                    utc_now_iso(),
                ),
            )


def row_to_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None
