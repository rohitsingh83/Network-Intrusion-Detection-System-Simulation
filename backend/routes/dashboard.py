from fastapi import APIRouter, Request, Query
from typing import Optional

router = APIRouter()

@router.get("/stats")
async def get_dashboard_stats(request: Request):
    db = request.app.state.db
    return db.get_dashboard_stats()

@router.get("/traffic")
async def get_traffic_timeline(request: Request, hours: int = Query(24, ge=1, le=168)):
    db = request.app.state.db
    return {"data": db.get_traffic_timeline(hours=hours)}

@router.get("/alerts")
async def get_alert_timeline(request: Request, hours: int = Query(24, ge=1, le=168)):
    db = request.app.state.db
    return {"data": db.get_alert_timeline(hours=hours)}

@router.get("/protocols")
async def get_protocol_distribution(request: Request):
    db = request.app.state.db
    return {"data": db.get_protocol_distribution()}

@router.get("/ports")
async def get_port_distribution(request: Request, limit: int = Query(20, ge=1, le=100)):
    db = request.app.state.db
    return {"data": db.get_port_distribution(limit=limit)}

@router.get("/sources")
async def get_top_sources(request: Request, limit: int = Query(10, ge=1, le=50)):
    db = request.app.state.db
    return {"data": db.get_top_source_ips(limit=limit)}

@router.get("/risk")
async def get_risk_distribution(request: Request):
    db = request.app.state.db
    return {"data": db.get_risk_distribution()}

@router.get("/severity")
async def get_severity_distribution(request: Request):
    db = request.app.state.db
    return {"data": db.get_severity_distribution()}
