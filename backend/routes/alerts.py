"""Alert queue, status transitions, and analyst-note endpoints."""

from fastapi import APIRouter, HTTPException, Query, Request, status

from backend.schemas import AlertStatusUpdate, AnalystNoteIn

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("")
def list_alerts(
    request: Request,
    severity: str | None = Query(default=None, max_length=20),
    protocol: str | None = Query(default=None, max_length=10),
    alert_type: str | None = Query(default=None, max_length=100),
    status_filter: str | None = Query(default=None, alias="status", max_length=30),
    hours: int | None = Query(default=None, ge=0, le=8760),
    limit: int = Query(default=100, ge=1, le=500),
):
    return {"items": request.app.state.service.list_alerts(
        severity=severity, protocol=protocol, alert_type=alert_type,
        status=status_filter, hours=hours, limit=limit,
    )}


@router.get("/{alert_id}")
def get_alert(alert_id: str, request: Request):
    result = request.app.state.service.get_alert(alert_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return result


@router.put("/{alert_id}/status")
def update_alert_status(alert_id: str, payload: AlertStatusUpdate, request: Request):
    try:
        result = request.app.state.service.update_alert_status(
            alert_id, payload.status, payload.note, payload.resolution_notes, payload.actor
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return result


@router.post("/{alert_id}/notes", status_code=status.HTTP_201_CREATED)
def add_analyst_note(alert_id: str, payload: AnalystNoteIn, request: Request):
    result = request.app.state.service.add_note(alert_id, payload.note, payload.author)
    if result is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return result
