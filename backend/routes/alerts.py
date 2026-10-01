from fastapi import APIRouter, Request, Query, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List
import uuid
import datetime

router = APIRouter()

class StatusUpdateModel(BaseModel):
    status: str
    analyst: Optional[str] = "SOC Analyst"

class NoteInputModel(BaseModel):
    note: str
    analyst: Optional[str] = "SOC Analyst"
    action: Optional[str] = "INVESTIGATION_NOTE"

@router.get("")
async def list_alerts(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    alert_type: Optional[str] = None,
    protocol: Optional[str] = None
):
    db = getattr(request.app.state, "db", None)
    if not db:
        return {"data": [], "count": 0, "limit": limit, "offset": offset}
    filters = {}
    if severity: filters["severity"] = severity
    if status: filters["status"] = status
    if alert_type: filters["alert_type"] = alert_type
    if protocol: filters["protocol"] = protocol

    alerts = db.get_alerts(limit=limit, offset=offset, filters=filters)
    return alerts

@router.get("/{alert_id}")
async def get_alert(alert_id: str, request: Request):
    db = getattr(request.app.state, "db", None)
    if not db:
        raise HTTPException(status_code=404, detail="Database unavailable")
    alert = db.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    notes = db.get_alert_notes(alert_id)
    alert["notes"] = notes
    return alert

@router.put("/{alert_id}/status")
async def update_alert_status(alert_id: str, update_data: StatusUpdateModel, request: Request):
    db = getattr(request.app.state, "db", None)
    if not db:
        raise HTTPException(status_code=404, detail="Database unavailable")
    alert = db.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    norm_status = update_data.status.strip().upper()
    valid_statuses = ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
    if norm_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of {valid_statuses}")
        
    db.update_alert_status(alert_id, norm_status, update_data.analyst)
    return {"message": "Status updated successfully", "status": norm_status}

@router.post("/{alert_id}/notes")
async def add_alert_note(alert_id: str, note_data: NoteInputModel, request: Request):
    db = getattr(request.app.state, "db", None)
    if not db:
        raise HTTPException(status_code=404, detail="Database unavailable")
    alert = db.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    note_dict = {
        "note_id": str(uuid.uuid4()),
        "alert_id": alert_id,
        "analyst": note_data.analyst or "SOC Analyst",
        "note": note_data.note,
        "action": note_data.action or "INVESTIGATION_NOTE",
        "created_at": datetime.datetime.utcnow().isoformat()
    }
    
    db.insert_note(note_dict)
    return {"message": "Note added successfully", "note_id": note_dict["note_id"]}
