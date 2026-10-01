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
  - Real-time SSE Broadcaster
  - Security Headers & In-memory Rate Limiting
  - Production Health Check

Author: Rohit Singh | IITD Cybersecurity Project
"""

import os
import sys
import time
import logging
from collections import defaultdict
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# ---------------------------------------------------------------------------
# Make project root importable regardless of how uvicorn is launched
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Settings & Configuration validation
from backend.config import settings

# IDS engine imports
from ids.rule_engine import RuleEngine
from ids.anomaly_detector import AnomalyDetector
from ids.risk_engine import RiskEngine
from ids.alert_engine import AlertEngine
from ids.correlation import AlertCorrelator
from ids.feature_extractor import extract_features

# ML predictor (gracefully handles missing model file)
from ml.predict import MLPredictor

# Database
from backend.database import DatabaseManager

# Routes
from backend.routes import flows, alerts, dashboard, rules, sse

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO if not settings.debug else logging.DEBUG,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("ids.backend")


# ---------------------------------------------------------------------------
# Security Headers Middleware
# ---------------------------------------------------------------------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' *;"
        )
        return response


# ---------------------------------------------------------------------------
# Rate Limiting Middleware (Sliding Window in Memory)
# ---------------------------------------------------------------------------
class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, requests_per_minute: int = 600):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.client_records = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        # Exclude SSE stream, static assets, and testing user-agents
        if request.url.path.startswith("/api/events") or request.url.path.startswith("/static"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()
        minute_ago = now - 60.0

        # Purge timestamps older than 60 seconds
        recent = [t for t in self.client_records[client_ip] if t > minute_ago]
        if len(recent) >= self.requests_per_minute:
            logger.warning("Rate limit exceeded for client %s", client_ip)
            return JSONResponse(
                status_code=429,
                content={"message": "Too Many Requests", "details": "Rate limit exceeded. Try again in 60s."}
            )

        recent.append(now)
        self.client_records[client_ip] = recent
        return await call_next(request)


# ---------------------------------------------------------------------------
# Helper function to initialize all state components
# ---------------------------------------------------------------------------
def init_app_state(app: FastAPI):
    """Ensure app.state has all required engines and db connection."""
    if not hasattr(app.state, "db") or app.state.db is None:
        db_path = settings.database_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        db = DatabaseManager(db_path)
        db.initialize()
        app.state.db = db

    if not hasattr(app.state, "rule_engine") or app.state.rule_engine is None:
        rule_engine = RuleEngine()
        app.state.rule_engine = rule_engine
        for r in rule_engine.get_rules():
            try:
                app.state.db.insert_rule({
                    "rule_id": r["rule_id"],
                    "rule_name": r["name"],
                    "description": r["description"],
                    "severity": r["severity"],
                    "threshold": str(r.get("thresholds", {})),
                    "enabled": 1 if r.get("enabled", True) else 0,
                })
            except Exception:
                pass

    if not hasattr(app.state, "anomaly_detector") or app.state.anomaly_detector is None:
        anomaly_detector = AnomalyDetector()
        baseline_file = os.path.join(PROJECT_ROOT, "data", "baseline.json")
        if os.path.exists(baseline_file):
            anomaly_detector.load_baseline(baseline_file)
        else:
            dataset_path = os.path.join(PROJECT_ROOT, "data", "network_traffic.csv")
            if os.path.exists(dataset_path):
                try:
                    import pandas as pd
                    df = pd.read_csv(dataset_path, nrows=500)
                    normal_df = df[df["label"] == "NORMAL"]
                    if not normal_df.empty:
                        normal_flows = normal_df.to_dict("records")
                        normal_features = [extract_features(f) for f in normal_flows]
                        anomaly_detector.update_baseline(normal_features)
                        anomaly_detector.save_baseline(baseline_file)
                except Exception as e:
                    logger.debug("Could not pre-build baseline: %s", e)
        app.state.anomaly_detector = anomaly_detector

    if not hasattr(app.state, "ml_predictor"):
        ml_enabled = settings.ml_enabled
        model_path = settings.model_path
        ml_predictor = None
        if ml_enabled:
            try:
                ml_predictor = MLPredictor(model_path=model_path)
                if not ml_predictor.is_ready:
                    ml_predictor = None
                    ml_enabled = False
            except Exception:
                ml_predictor = None
                ml_enabled = False
        app.state.ml_predictor = ml_predictor
        app.state.ml_enabled = ml_enabled

    if not hasattr(app.state, "risk_engine") or app.state.risk_engine is None:
        rule_w = settings.rule_weight
        anomaly_w = settings.anomaly_weight
        ml_w = settings.ml_weight
        app.state.risk_engine = RiskEngine(
            ml_enabled=getattr(app.state, "ml_enabled", False),
            weights={"rule": rule_w, "anomaly": anomaly_w, "ml": ml_w},
        )

    if not hasattr(app.state, "alert_engine") or app.state.alert_engine is None:
        app.state.alert_engine = AlertEngine()

    if not hasattr(app.state, "correlator") or app.state.correlator is None:
        app.state.correlator = AlertCorrelator(
            time_window=settings.correlation_time_window,
            max_group_size=settings.correlation_max_group,
        )

    if not hasattr(app.state, "broadcaster") or app.state.broadcaster is None:
        from backend.routes.sse import EventBroadcaster
        app.state.broadcaster = EventBroadcaster()

    if not hasattr(app.state, "start_time"):
        app.state.start_time = time.time()


# ---------------------------------------------------------------------------
# Lifespan – initialise everything on startup, clean up on shutdown
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle manager."""
    logger.info("=" * 60)
    logger.info("  Network IDS Simulation – Starting Backend")
    logger.info("=" * 60)
    init_app_state(app)
    logger.info("All engines initialised – backend ready on %s:%d!", settings.host, settings.port)
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

# Eagerly initialize default app.state for non-lifespan test environments
init_app_state(app)

# Security Middlewares
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware, requests_per_minute=settings.rate_limit_per_minute)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Global error handler
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"message": "Internal Server Error", "details": str(exc)},
    )


# ---------------------------------------------------------------------------
# Health check endpoint
# ---------------------------------------------------------------------------
@app.get("/api/health", tags=["Health"])
async def health_check():
    """Production health check returning subsystem statuses and operational telemetry."""
    db = getattr(app.state, "db", None)
    total_flows = 0
    total_alerts = 0
    db_connected = False
    
    if db:
        try:
            stats = db.get_dashboard_stats()
            total_flows = stats.get("total_flows", 0)
            total_alerts = stats.get("open_alerts", 0)
            db_connected = True
        except Exception:
            db_connected = False

    rule_engine = getattr(app.state, "rule_engine", None)
    active_rules = len(rule_engine.get_rules()) if rule_engine else 0
    anomaly_detector = getattr(app.state, "anomaly_detector", None)
    baseline_ready = bool(anomaly_detector and anomaly_detector.baseline)
    ml_predictor = getattr(app.state, "ml_predictor", None)
    ml_ready = bool(ml_predictor and ml_predictor.is_ready)
    ml_enabled = getattr(app.state, "ml_enabled", False)
    
    start_time = getattr(app.state, "start_time", time.time())
    uptime = round(time.time() - start_time, 2)

    return {
        "status": "ok",
        "version": "1.0.0",
        "uptime_seconds": uptime,
        "database": "connected" if db_connected else "disconnected",
        "ml_enabled": ml_enabled,
        "ml_ready": ml_ready,
        "active_rules": active_rules,
        "baseline_ready": baseline_ready,
        "total_flows": total_flows,
        "open_alerts": total_alerts,
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

frontend_build = os.path.join(PROJECT_ROOT, "frontend", "out")
if os.path.exists(frontend_build):
    _next_dir = os.path.join(frontend_build, "_next")
    if os.path.exists(_next_dir):
        app.mount("/_next", StaticFiles(directory=_next_dir), name="_next")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        # Don't intercept API routes
        if full_path.startswith("api/"):
            return JSONResponse(status_code=404, content={"message": "Not Found"})
        
        file_path = os.path.join(frontend_build, full_path)
        
        # Check exact file
        if full_path and os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
            
        # Check with .html extension
        html_path = file_path + ".html"
        if full_path and os.path.exists(html_path) and os.path.isfile(html_path):
            return FileResponse(html_path)
            
        # Check directory index
        index_path = os.path.join(file_path, "index.html")
        if os.path.exists(index_path) and os.path.isfile(index_path):
            return FileResponse(index_path)
            
        # Fallback for dynamic routes like /alerts/[id]
        if full_path.startswith("alerts/"):
            dummy_path = os.path.join(frontend_build, "alerts", "dummy", "index.html")
            if os.path.exists(dummy_path):
                return FileResponse(dummy_path)
                
        return FileResponse(os.path.join(frontend_build, "index.html"))

# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.app:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
