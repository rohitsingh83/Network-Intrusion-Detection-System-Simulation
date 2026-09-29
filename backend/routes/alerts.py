from fastapi import APIRouter, Request, Query, HTTPException
from pydantic import BaseModel
from typing import Optional, List
import uuid
import datetime

router = APIRouter()

class StatusUpdateModel(BaseModel):
    status: str
    analyst: Optional[str] = None

class NoteInputModel(BaseModel):
    note: str
    analyst: str
    action: str

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
    db = request.app.state.db
    filters = {}
    if severity: filters["severity"] = severity
    if status: filters["status"] = status
    if alert_type: filters["alert_type"] = alert_type
    if protocol: filters["protocol"] = protocol

    alerts = db.get_alerts(limit=limit, offset=offset, filters=filters)
    return {"data": alerts, "count": len(alerts), "limit": limit, "offset": offset}

@router.get("/{alert_id}")
async def get_alert(alert_id: str, request: Request):
    db = request.app.state.db
    alert = db.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    notes = db.get_alert_notes(alert_id)
    alert["notes"] = notes
    return alert

@router.put("/{alert_id}/status")
async def update_alert_status(alert_id: str, update_data: StatusUpdateModel, request: Request):
    db = request.app.state.db
    alert = db.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    valid_statuses = ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
    if update_data.status not in valid_statuses:
        raise HTTPException(status_code=400, detail="Invalid status")
        
    db.update_alert_status(alert_id, update_data.status, update_data.analyst)
    return {"message": "Status updated successfully", "status": update_data.status}

@router.post("/{alert_id}/notes")
async def add_alert_note(alert_id: str, note_data: NoteInputModel, request: Request):
    db = request.app.state.db
    alert = db.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    note_dict = {
        "note_id": str(uuid.uuid4()),
        "alert_id": alert_id,
        "analyst": note_data.analyst,
        "note": note_data.note,
        "action": note_data.action,
        "created_at": datetime.datetime.utcnow().isoformat()
    }
    
    db.insert_note(note_dict)
    return {"message": "Note added successfully", "note_id": note_dict["note_id"]}
