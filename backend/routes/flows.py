"""
Flow Endpoints – POST /api/flows, GET /api/flows, GET /api/flows/{id}
=====================================================================
Receives network-flow records, runs them through the full IDS pipeline
(feature extraction → rule engine → anomaly detection → ML → risk
scoring → alert generation), persists results, and pushes SSE events.
"""

import uuid
import datetime
import logging
from typing import Optional

from fastapi import APIRouter, Request, Query, HTTPException
from pydantic import BaseModel, Field

from ids.feature_extractor import extract_features, validate_flow

logger = logging.getLogger("ids.routes.flows")
router = APIRouter()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class FlowInput(BaseModel):
    """Incoming network-flow record from the traffic simulator."""
    source_ip: str
    destination_ip: str
    source_port: int = Field(ge=0, le=65535)
    destination_port: int = Field(ge=0, le=65535)
    protocol: str = "TCP"
    packet_count: int = 0
    byte_count: int = 0
    duration_seconds: float = Field(default=0.0, alias="duration")
    connection_count: int = 0
    failed_connection_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    average_packet_size: float = 0.0

    class Config:
        populate_by_name = True       # accept both "duration" and "duration_seconds"


class FlowAnalysisResponse(BaseModel):
    flow_id: str
    risk_score: float
    classification: str
    severity: str
    rules_matched: list
    anomaly_score: float
    ml_score: Optional[float] = None
    alert_generated: bool
    alert_id: Optional[str] = None


# ---------------------------------------------------------------------------
# POST /api/flows – full IDS pipeline
# ---------------------------------------------------------------------------
@router.post("", response_model=FlowAnalysisResponse)
async def process_flow(flow: FlowInput, request: Request):
    """
    Receive a network flow, run through the complete IDS pipeline, store
    the flow and any generated alert in the database, and push a
    Server-Sent Event notification.
    """
    db = request.app.state.db
    rule_engine = request.app.state.rule_engine
    anomaly_detector = request.app.state.anomaly_detector
    risk_engine = request.app.state.risk_engine
    alert_engine = request.app.state.alert_engine
    ml_predictor = request.app.state.ml_predictor
    broadcaster = getattr(request.app.state, "broadcaster", None)

    flow_id = f"FLW-{uuid.uuid4().hex[:12].upper()}"
    timestamp = datetime.datetime.utcnow().isoformat()

    # ---- 1. Build raw flow dict -----------------------------------------
    raw_flow = flow.model_dump(by_alias=False)
    raw_flow["flow_id"] = flow_id
    raw_flow["timestamp"] = timestamp

    # ---- 2. Feature extraction ------------------------------------------
    features = extract_features(raw_flow)

    # ---- 3. Signature / rule-based detection ----------------------------
    rule_results = rule_engine.analyze_flow(features, raw_flow=raw_flow)

    # ---- 4. Anomaly detection -------------------------------------------
    anomaly_result = anomaly_detector.calculate_anomaly_score(features)

    # ---- 5. ML prediction (optional) ------------------------------------
    ml_score = None
    if ml_predictor:
        try:
            ml_out = ml_predictor.predict(features)
            ml_score = ml_out.get("probability")
        except Exception as exc:
            logger.debug("ML prediction skipped: %s", exc)

    # ---- 6. Risk scoring ------------------------------------------------
    risk_result = risk_engine.calculate_risk_score(
        rule_results, anomaly_result, ml_result=ml_score
    )

    # ---- 7. Persist flow ------------------------------------------------
    flow_record = {
        "flow_id": flow_id,
        "timestamp": timestamp,
        "source_ip": raw_flow["source_ip"],
        "destination_ip": raw_flow["destination_ip"],
        "source_port": raw_flow["source_port"],
        "destination_port": raw_flow["destination_port"],
        "protocol": raw_flow["protocol"],
        "packet_count": raw_flow["packet_count"],
        "byte_count": raw_flow["byte_count"],
        "duration": raw_flow["duration_seconds"],
        "connection_count": raw_flow["connection_count"],
        "failed_connection_count": raw_flow["failed_connection_count"],
        "syn_count": raw_flow["syn_count"],
        "rst_count": raw_flow["rst_count"],
        "average_packet_size": raw_flow["average_packet_size"],
        "risk_score": risk_result["risk_score"],
        "classification": risk_result["classification"],
        "created_at": timestamp,
    }
    db.insert_flow(flow_record)

    # ---- 8. Alert generation --------------------------------------------
    alert = alert_engine.generate_alert(
        flow=raw_flow,
        features=features,
        risk_result=risk_result,
        rule_results=rule_results,
        anomaly_result=anomaly_result,
        ml_result=ml_score,
    )

    alert_generated = alert is not None
    alert_id = None

    if alert:
        alert_id = alert["alert_id"]
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
            "status": "NEW",
            "source_ip": raw_flow["source_ip"],
            "destination_ip": raw_flow["destination_ip"],
            "protocol": raw_flow["protocol"],
            "source_port": raw_flow["source_port"],
            "destination_port": raw_flow["destination_port"],
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        db.insert_alert(alert_record)
        logger.info(
            "ALERT %s | %s | %s → %s | Risk %s | %s",
            alert_id,
            alert["severity"],
            raw_flow["source_ip"],
            raw_flow["destination_ip"],
            risk_result["risk_score"],
            alert["alert_type"],
        )

        # Push SSE event
        if broadcaster:
            try:
                await broadcaster.broadcast("new_alert", alert_record)
            except Exception:
                pass

    # Optional: store ML result
    if ml_score is not None:
        try:
            db.insert_model_result({
                "result_id": f"MLR-{uuid.uuid4().hex[:8].upper()}",
                "flow_id": flow_id,
                "model_name": "RandomForest",
                "prediction": "SUSPICIOUS" if ml_score > 0.5 else "NORMAL",
                "probability": ml_score,
                "created_at": timestamp,
            })
        except Exception:
            pass

    # Push SSE flow event
    if broadcaster:
        try:
            await broadcaster.broadcast("new_flow", {
                "flow_id": flow_id,
                "classification": risk_result["classification"],
                "risk_score": risk_result["risk_score"],
            })
        except Exception:
            pass

    return FlowAnalysisResponse(
        flow_id=flow_id,
        risk_score=risk_result["risk_score"],
        classification=risk_result["classification"],
        severity=risk_result["severity"],
        rules_matched=[r["rule_id"] for r in rule_results],
        anomaly_score=anomaly_result.get("anomaly_score", 0),
        ml_score=ml_score,
        alert_generated=alert_generated,
        alert_id=alert_id,
    )


# ---------------------------------------------------------------------------
# GET /api/flows – list with pagination & filters
# ---------------------------------------------------------------------------
@router.get("")
async def list_flows(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    protocol: Optional[str] = None,
    classification: Optional[str] = None,
):
    """List network flows with optional filtering and pagination."""
    db = request.app.state.db
    filters = {}
    if protocol:
        filters["protocol"] = protocol
    if classification:
        filters["classification"] = classification

    flows_data = db.get_flows(limit=limit, offset=offset, filters=filters)
    return {"data": flows_data, "count": len(flows_data), "limit": limit, "offset": offset}


# ---------------------------------------------------------------------------
# GET /api/flows/{flow_id}
# ---------------------------------------------------------------------------
@router.get("/{flow_id}")
async def get_flow(flow_id: str, request: Request):
    """Get complete details for a specific network flow."""
    db = request.app.state.db
    flow_data = db.get_flow(flow_id)
    if not flow_data:
        raise HTTPException(status_code=404, detail="Flow not found")
    return flow_data
