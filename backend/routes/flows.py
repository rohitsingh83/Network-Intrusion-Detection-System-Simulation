"""Flow intake and query endpoints."""

from fastapi import APIRouter, HTTPException, Query, Request, status

from backend.schemas import FlowIn
from backend.services import DuplicateFlowError

router = APIRouter(prefix="/api/flows", tags=["flows"])


@router.post("", status_code=status.HTTP_201_CREATED)
def ingest_flow(payload: FlowIn, request: Request):
    try:
        return request.app.state.service.ingest_flow(payload.model_dump())
    except DuplicateFlowError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("")
def list_flows(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    search: str | None = Query(default=None, max_length=120),
):
    items = request.app.state.service.list_flows(limit, search)
    return {"items": items, "count": len(items)}


@router.get("/{flow_id}")
def get_flow(flow_id: str, request: Request):
    result = request.app.state.service.get_flow(flow_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Flow not found")
    return result
