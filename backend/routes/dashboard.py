"""Read-optimized dashboard analytics."""

from fastapi import APIRouter, Query, Request

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats")
def dashboard_stats(request: Request):
    return request.app.state.service.dashboard_stats()


@router.get("/traffic")
def dashboard_traffic(
    request: Request,
    hours: int = Query(default=24, ge=1, le=720),
    bucket_minutes: int | None = Query(default=None, ge=1, le=1440),
):
    return request.app.state.service.dashboard_traffic(hours, bucket_minutes)


@router.get("/alerts")
def dashboard_alert_analytics(request: Request, hours: int = Query(default=24, ge=1, le=720)):
    analytics = request.app.state.service.dashboard_traffic(hours)
    return {
        "severity_distribution": analytics["severity_distribution"],
        "top_alert_types": analytics["top_alert_types"],
        "top_source_ips": analytics["top_source_ips"],
        "alert_timeline": [
            {"timestamp": item["timestamp"], "alerts": item["alerts"]}
            for item in analytics["timeline"]
        ],
    }
