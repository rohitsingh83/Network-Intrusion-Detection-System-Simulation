"""SentinelFlow FastAPI application and same-origin dashboard host."""

from __future__ import annotations

import hmac
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.database import DEFAULT_DB_PATH, init_db
from backend.routes.alerts import router as alerts_router
from backend.routes.dashboard import router as dashboard_router
from backend.routes.flows import router as flows_router
from backend.routes.rules import router as rules_router
from backend.routes.simulation import router as simulation_router
from backend.services import IDSService

ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = ROOT / "frontend"
FRONTEND_SRC = FRONTEND_DIR / "src"


def create_app(
    db_path: str | Path | None = None,
    dataset_path: str | Path | None = None,
    seed_demo: bool | None = None,
) -> FastAPI:
    selected_db = Path(db_path or DEFAULT_DB_PATH)
    if seed_demo is None:
        seed_demo = os.getenv("IDS_SEED_DEMO", "true").strip().lower() not in {"0", "false", "no"}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_db(selected_db)
        app.state.db_path = selected_db
        app.state.service = IDSService(selected_db, dataset_path=dataset_path)
        if seed_demo:
            app.state.service.seed_demo_if_empty()
        yield

    app = FastAPI(
        title="SentinelFlow IDS Simulation API",
        version="1.0.0",
        description="Defensive, synthetic network-flow IDS simulation. No packet capture or transmission is performed.",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "OPTIONS"],
        allow_headers=["Content-Type", "X-API-Key"],
    )

    @app.middleware("http")
    async def optional_write_api_key(request: Request, call_next):
        expected = os.getenv("IDS_API_KEY", "").strip()
        if expected and request.url.path.startswith("/api/") and request.method not in {"GET", "HEAD", "OPTIONS"}:
            supplied = request.headers.get("X-API-Key", "")
            if not hmac.compare_digest(expected, supplied):
                return JSONResponse(status_code=401, content={"detail": "Valid X-API-Key required for write operations"})
        return await call_next(request)

    app.include_router(flows_router)
    app.include_router(alerts_router)
    app.include_router(dashboard_router)
    app.include_router(rules_router)
    app.include_router(simulation_router)

    @app.get("/health", tags=["system"])
    def health():
        return {"status": "ok", "service": "sentinelflow", "mode": "synthetic-data-only"}

    @app.get("/api/system", tags=["system"])
    def system_status(request: Request):
        service = request.app.state.service
        return {
            "name": "SentinelFlow",
            "version": "1.0.0",
            "ml_enabled": service.ml_enabled,
            "ml_model": service.model_bundle.get("model_name") if service.model_bundle else None,
            "anomaly_baseline_fitted": service.pipeline.anomaly_detector.fitted,
            "data_mode": "synthetic-flow-records-only",
            "api_key_protected_writes": bool(os.getenv("IDS_API_KEY", "").strip()),
        }

    if FRONTEND_SRC.exists():
        app.mount("/src", StaticFiles(directory=FRONTEND_SRC), name="frontend-src")

    @app.get("/", include_in_schema=False)
    def dashboard():
        index_file = FRONTEND_DIR / "index.html"
        if not index_file.exists():
            return JSONResponse({"message": "Build files missing. See README.md."}, status_code=404)
        return FileResponse(index_file)

    return app


app = create_app()
