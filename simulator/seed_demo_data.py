"""
Database Seeder for Network IDS Simulation
==========================================
Seeds the database with pre-processed flows and alerts from the
synthetic dataset so that the dashboard is immediately vibrant,
rich with analytics, and populated with triage records on launch.

Author: Rohit Singh | IITD Cybersecurity Project
"""

import os
import sys
import datetime
import uuid
import pandas as pd

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.database import DatabaseManager
from ids.feature_extractor import extract_features
from ids.rule_engine import RuleEngine
from ids.anomaly_detector import AnomalyDetector
from ids.risk_engine import RiskEngine
from ids.alert_engine import AlertEngine
from ml.predict import MLPredictor


def seed_database(num_records: int = 400, db_path: str = "data/ids_database.db"):
    print("=" * 60)
    print("  Seeding IDS Security Database with Realistic Telemetry")
    print("=" * 60)

    # 1. Initialize DB
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    db = DatabaseManager(db_path)
    db.initialize()

    # 2. Initialize Detection Engines
    rule_engine = RuleEngine()
    for r in rule_engine.get_rules():
        try:
            db.insert_rule({
                "rule_id": r["rule_id"],
                "rule_name": r["name"],
                "description": r["description"],
                "severity": r["severity"],
                "threshold": str(r.get("thresholds", {})),
                "enabled": 1 if r.get("enabled", True) else 0,
            })
        except Exception:
            pass

    anomaly_detector = AnomalyDetector()
    csv_path = os.path.join(PROJECT_ROOT, "data", "network_traffic.csv")
    if not os.path.exists(csv_path):
        print(f"Error: {csv_path} not found. Generate dataset first.")
        return

    df = pd.read_csv(csv_path)
    normal_df = df[df["label"] == "NORMAL"]
    normal_features = [extract_features(r) for r in normal_df.head(1000).to_dict("records")]
    anomaly_detector.update_baseline(normal_features)

    # ML Predictor
    ml_predictor = None
    try:
        model_path = os.path.join(PROJECT_ROOT, "models", "ids_model.joblib")
        if os.path.exists(model_path):
            ml_predictor = MLPredictor(model_path=model_path)
            if not ml_predictor.is_ready:
                ml_predictor = None
    except Exception:
        pass

    risk_engine = RiskEngine(
        ml_enabled=(ml_predictor is not None),
        weights={"rule": 0.4, "anomaly": 0.3, "ml": 0.3} if ml_predictor else {"rule": 0.6, "anomaly": 0.4}
    )
    alert_engine = AlertEngine()

    # 3. Process sample flows
    sample_df = df.head(num_records)
    print(f"Processing {len(sample_df)} flow records through IDS pipeline...")

    flows_count = 0
    alerts_count = 0

    now = datetime.datetime.utcnow()

    for idx, row in sample_df.iterrows():
        raw_flow = row.to_dict()
        # Spread timestamps over the last 24 hours for realistic timeline charts
        minutes_ago = (num_records - idx) * (1440 // num_records)
        flow_time = (now - datetime.timedelta(minutes=minutes_ago)).isoformat()
        
        flow_id = raw_flow.get("flow_id", f"FLW-{uuid.uuid4().hex[:12].upper()}")
        raw_flow["flow_id"] = flow_id
        raw_flow["timestamp"] = flow_time

        features = extract_features(raw_flow)
        rule_results = rule_engine.analyze_flow(features, raw_flow=raw_flow)
        anomaly_result = anomaly_detector.calculate_anomaly_score(features)

        ml_score = None
        if ml_predictor:
            try:
                res = ml_predictor.predict(features)
                ml_score = res.get("probability")
            except Exception:
                pass

        risk_result = risk_engine.calculate_risk_score(rule_results, anomaly_result, ml_result=ml_score)

        flow_record = {
            "flow_id": flow_id,
            "timestamp": flow_time,
            "source_ip": raw_flow["source_ip"],
            "destination_ip": raw_flow["destination_ip"],
            "source_port": int(raw_flow["source_port"]),
            "destination_port": int(raw_flow["destination_port"]),
            "protocol": raw_flow["protocol"],
            "packet_count": int(raw_flow["packet_count"]),
            "byte_count": int(raw_flow["byte_count"]),
            "duration": float(raw_flow["duration_seconds"]),
            "connection_count": int(raw_flow["connection_count"]),
            "failed_connection_count": int(raw_flow["failed_connection_count"]),
            "syn_count": int(raw_flow["syn_count"]),
            "rst_count": int(raw_flow["rst_count"]),
            "average_packet_size": float(raw_flow["average_packet_size"]),
            "risk_score": risk_result["risk_score"],
            "classification": risk_result["classification"],
            "created_at": flow_time,
        }
        db.insert_flow(flow_record)
        flows_count += 1

        alert = alert_engine.generate_alert(
            flow=raw_flow,
            features=features,
            risk_result=risk_result,
            rule_results=rule_results,
            anomaly_result=anomaly_result,
            ml_result=ml_score,
        )

        if alert:
            alerts_count += 1
            # Randomly set some to INVESTIGATING or RESOLVED for realistic status breakdown
            if alerts_count % 5 == 0:
                status = "RESOLVED"
            elif alerts_count % 3 == 0:
                status = "INVESTIGATING"
            elif alerts_count % 11 == 0:
                status = "FALSE_POSITIVE"
            else:
                status = "NEW"

            alert_record = {
                "alert_id": alert["alert_id"],
                "flow_id": flow_id,
                "rule_id": ",".join(alert.get("rule_ids", [])),
                "alert_type": alert.get("alert_type", "Unknown"),
                "severity": alert.get("severity", "LOW"),
                "description": alert.get("description", ""),
                "risk_score": alert.get("risk_score", 0),
                "anomaly_score": alert.get("anomaly_score", 0),
                "ml_score": ml_score,
                "status": status,
                "source_ip": raw_flow["source_ip"],
                "destination_ip": raw_flow["destination_ip"],
                "protocol": raw_flow["protocol"],
                "source_port": int(raw_flow["source_port"]),
                "destination_port": int(raw_flow["destination_port"]),
                "created_at": flow_time,
                "updated_at": flow_time,
            }
            db.insert_alert(alert_record)

            # Add sample analyst notes for investigated alerts
            if status in ["INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]:
                db.insert_note({
                    "note_id": f"NOT-{uuid.uuid4().hex[:8].upper()}",
                    "alert_id": alert["alert_id"],
                    "analyst": "SOC-Analyst-Tier1",
                    "note": f"Initial triage completed. Source {raw_flow['source_ip']} inspected. Flow pattern: {alert.get('alert_type')}.",
                    "action": "TRIAGE",
                    "created_at": flow_time
                })
                if status == "RESOLVED":
                    db.insert_note({
                        "note_id": f"NOT-{uuid.uuid4().hex[:8].upper()}",
                        "alert_id": alert["alert_id"],
                        "analyst": "SOC-Lead",
                        "note": "Firewall policy confirmed blocking or benign authorized activity verified. Ticket closed.",
                        "action": "RESOLVE",
                        "created_at": flow_time
                    })

    print(f"[OK] Seed complete: {flows_count} flows inserted, {alerts_count} security alerts generated.")
    stats = db.get_dashboard_stats()
    print("Database Snapshot:", stats)


if __name__ == "__main__":
    seed_database()
