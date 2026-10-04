"""Detection-rule listing and safe threshold toggling."""

from fastapi import APIRouter, HTTPException, Request

from backend.schemas import RuleUpdate

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("")
def list_rules(request: Request):
    return {"items": request.app.state.service.list_rules()}


@router.put("/{rule_id}")
def update_rule(rule_id: str, payload: RuleUpdate, request: Request):
    result = request.app.state.service.update_rule(rule_id, payload.enabled, payload.threshold)
    if result is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return result
