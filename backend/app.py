"""
Network IDS Simulation - Main FastAPI Application
==================================================
Central backend server that orchestrates all IDS components:
  - Feature Extractor
  - Rule-Based Detection Engine
  - Anomaly Detection Engine
  - Risk Scoring Engine
  - Alert Generation Engine
  - Alert Correlation
  - Optional ML Predictor

Author: Rohit Singh | IITD Cybersecurity Project
"""

import os
import sys
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Make project root importable regardless of how uvicorn is launched
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# IDS engine imports
from ids.rule_engine import RuleEngine
from ids.anomaly_detector import AnomalyDetector
from ids.risk_engine import RiskEngine
from ids.alert_engine import AlertEngine
from ids.correlation import AlertCorrelator
from ids.feature_extractor import extract_features

# ML predictor (optional – gracefully handles missing model file)
from ml.predict import MLPredictor

# Database
from backend.database import DatabaseManager

# Routes
from backend.routes import flows, alerts, dashboard, rules, sse

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("ids.backend")

# ---------------------------------------------------------------------------
# Lifespan – initialise everything on startup, clean up on shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle manager."""
    logger.info("=" * 60)
    logger.info("  Network IDS Simulation – Starting Backend")
    logger.info("=" * 60)

    # ---- Database --------------------------------------------------------
    db_path = os.environ.get("DATABASE_PATH", "data/ids_database.db")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    db = DatabaseManager(db_path)
    db.initialize()
    app.state.db = db
    logger.info("Database initialised at %s", db_path)

    # ---- Rule Engine -----------------------------------------------------
    rule_engine = RuleEngine()
    app.state.rule_engine = rule_engine
    logger.info("Rule engine loaded – %d rules active", len(rule_engine.get_rules()))

    # Seed rules into database for the /api/rules endpoint
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
            pass  # rule already exists from a previous run

    # ---- Anomaly Detector ------------------------------------------------
    anomaly_detector = AnomalyDetector()

    # Build baseline from existing dataset (if available)
    dataset_path = os.path.join(PROJECT_ROOT, "data", "network_traffic.csv")
    if os.path.exists(dataset_path):
        import pandas as pd

        df = pd.read_csv(dataset_path)
        normal_df = df[df["label"] == "NORMAL"]
        if not normal_df.empty:
            normal_flows = normal_df.to_dict("records")
            normal_features = [extract_features(f) for f in normal_flows]
            anomaly_detector.update_baseline(normal_features)
            logger.info(
                "Anomaly baseline built from %d normal flows", len(normal_features)
            )

    app.state.anomaly_detector = anomaly_detector

    # ---- ML Predictor (optional) -----------------------------------------
    ml_enabled = os.environ.get("ML_ENABLED", "true").lower() == "true"
    model_path = os.environ.get("MODEL_PATH", "models/ids_model.joblib")
    ml_predictor = None
    if ml_enabled:
        try:
            ml_predictor = MLPredictor(model_path=model_path)
            if ml_predictor.is_ready:
                logger.info("ML model loaded from %s", model_path)
            else:
                logger.warning("ML model not ready – running without ML")
                ml_predictor = None
                ml_enabled = False
        except Exception as exc:
            logger.warning("ML model not available (%s) – running without ML", exc)
            ml_predictor = None
            ml_enabled = False

    app.state.ml_predictor = ml_predictor
    app.state.ml_enabled = ml_enabled

    # ---- Risk Engine -----------------------------------------------------
    rule_w = float(os.environ.get("RULE_WEIGHT", 0.4 if ml_enabled else 0.6))
    anomaly_w = float(os.environ.get("ANOMALY_WEIGHT", 0.3 if ml_enabled else 0.4))
    ml_w = float(os.environ.get("ML_WEIGHT", 0.3 if ml_enabled else 0.0))
    risk_engine = RiskEngine(
        ml_enabled=ml_enabled,
        weights={"rule": rule_w, "anomaly": anomaly_w, "ml": ml_w},
    )
    app.state.risk_engine = risk_engine
    logger.info(
        "Risk engine ready (ML %s) – weights: rule=%.1f anomaly=%.1f ml=%.1f",
        "ON" if ml_enabled else "OFF",
        rule_w,
        anomaly_w,
        ml_w,
    )

    # ---- Alert Engine & Correlator ---------------------------------------
    app.state.alert_engine = AlertEngine()
    app.state.correlator = AlertCorrelator(
        time_window=int(os.environ.get("CORRELATION_TIME_WINDOW", 60)),
        max_group_size=int(os.environ.get("CORRELATION_MAX_GROUP", 100)),
    )

    # ---- SSE Broadcaster -------------------------------------------------
    from backend.routes.sse import EventBroadcaster

    app.state.broadcaster = EventBroadcaster()

    logger.info("All engines initialised – backend ready!")
    logger.info("=" * 60)

    yield  # ---- application is running ----

    logger.info("Shutting down Network IDS backend …")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Network IDS Simulation API",
    description=(
        "Defensive Network Intrusion Detection System Simulation – "
        "provides synthetic traffic analysis, hybrid detection "
        "(signature + anomaly + ML), alert management, and SOC dashboard."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS (allow React dev server on port 3000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Global error handler
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error("Unhandled exception: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"message": "Internal Server Error", "details": str(exc)},
    )


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.get("/api/health", tags=["Health"])
async def health_check():
    return {
        "status": "ok",
        "version": "1.0.0",
        "ml_enabled": getattr(app.state, "ml_enabled", False),
    }


# ---------------------------------------------------------------------------
# Mount route modules
# ---------------------------------------------------------------------------
app.include_router(flows.router,     prefix="/api/flows",     tags=["Flows"])
app.include_router(alerts.router,    prefix="/api/alerts",    tags=["Alerts"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(rules.router,     prefix="/api/rules",     tags=["Rules"])
app.include_router(sse.router,       prefix="/api/events",    tags=["Events"])

# ---------------------------------------------------------------------------
# Mount Production Frontend (React Build)
# ---------------------------------------------------------------------------
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

frontend_build = os.path.join(PROJECT_ROOT, "frontend", "build")
if os.path.exists(frontend_build):
    static_dir = os.path.join(frontend_build, "static")
    if os.path.exists(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        # Don't intercept API routes
        if full_path.startswith("api/"):
            return JSONResponse(status_code=404, content={"message": "Not Found"})
        file_path = os.path.join(frontend_build, full_path)
        if full_path and os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(frontend_build, "index.html"))

# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.app:app",
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", 8000)),
        reload=True,
    )
