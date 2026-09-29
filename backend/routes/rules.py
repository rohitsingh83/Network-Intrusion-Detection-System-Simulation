from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from typing import Optional

router = APIRouter()

class RuleUpdateModel(BaseModel):
    threshold: Optional[float] = None
    enabled: Optional[int] = None
    severity: Optional[str] = None

@router.get("")
async def list_rules(request: Request):
    db = request.app.state.db
    return {"data": db.get_rules()}

@router.put("/{rule_id}")
async def update_rule(rule_id: str, rule_update: RuleUpdateModel, request: Request):
    db = request.app.state.db
    
    update_data = {}
    if rule_update.threshold is not None:
        update_data["threshold"] = rule_update.threshold
    if rule_update.enabled is not None:
        update_data["enabled"] = rule_update.enabled
    if rule_update.severity is not None:
        update_data["severity"] = rule_update.severity
        
    if not update_data:
        raise HTTPException(status_code=400, detail="No valid update fields provided")
        
    db.update_rule(rule_id, **update_data)
    
    # In a full system, you'd want to tell the RuleEngine to reload its rules here
    
    return {"message": "Rule updated successfully", "rule_id": rule_id, "updated_fields": update_data}
