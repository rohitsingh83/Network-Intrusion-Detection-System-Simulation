"""Synthetic replay endpoints. These create records only; they emit no packets."""

from random import Random
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request

from backend.schemas import ReplayRequest
from backend.services import DuplicateFlowError
from simulator.scenarios import ALL_SCENARIOS, choose_scenario, make_synthetic_flow

router = APIRouter(prefix="/api/simulation", tags=["simulation"])


@router.post("/replay")
def replay(payload: ReplayRequest, request: Request):
    rng = Random(payload.seed)
    results = []
    for index in range(payload.count):
        scenario = choose_scenario(payload.mode, index, rng)
        flow = make_synthetic_flow(
            scenario,
            flow_id=f"WEB-{uuid4().hex[:12].upper()}",
            rng=rng,
        )
        try:
            results.append(request.app.state.service.ingest_flow(flow))
        except DuplicateFlowError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "mode": payload.mode,
        "records_processed": len(results),
        "alerts_created_or_correlated": sum(1 for result in results if result.get("alert")),
        "items": results,
        "notice": "Synthetic flow records only. No packets were transmitted.",
    }


@router.post("/scenario/{scenario_type}")
def replay_scenario(scenario_type: str, request: Request, count: int = 1):
    normalized = scenario_type.upper()
    if normalized not in ALL_SCENARIOS:
        raise HTTPException(status_code=404, detail="Unknown synthetic scenario")
    if count < 1 or count > 50:
        raise HTTPException(status_code=422, detail="count must be between 1 and 50")
    results = []
    source = "192.0.2.77" if normalized in {"MULTI_PORT_PROBING_PATTERN", "HIGH_CONNECTION_RATE"} else None
    for _ in range(count):
        flow = make_synthetic_flow(
            normalized, flow_id=f"LAB-{uuid4().hex[:12].upper()}",
            source_ip=source, rng=Random(),
        )
        results.append(request.app.state.service.ingest_flow(flow))
    return {"scenario_type": normalized, "records_processed": len(results), "items": results,
            "notice": "Synthetic flow records only. No packets were transmitted."}
