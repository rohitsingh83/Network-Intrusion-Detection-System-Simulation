"""
Server-Sent Events (SSE) – real-time alert & flow notifications
================================================================
Provides a GET /stream endpoint that pushes new_alert and new_flow
events to connected dashboard clients.
"""

import asyncio
import json
import logging

from fastapi import APIRouter, Request
from sse_starlette.sse import EventSourceResponse

logger = logging.getLogger("ids.routes.sse")
router = APIRouter()


class EventBroadcaster:
    """Fan-out broadcaster – each connected client gets its own asyncio.Queue."""

    def __init__(self):
        self.queues: list[asyncio.Queue] = []

    async def broadcast(self, event_type: str, data: dict):
        """Push an event to every connected subscriber."""
        # Make sure data is JSON-serialisable (convert non-serialisable types)
        try:
            payload = json.dumps(data, default=str)
        except Exception:
            payload = json.dumps({"event": event_type})

        message = {"event": event_type, "data": payload}
        dead = []
        for q in self.queues:
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self.queues.remove(q)

    async def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self.queues.append(q)
        logger.info("SSE client subscribed (%d total)", len(self.queues))
        return q

    def unsubscribe(self, q: asyncio.Queue):
        if q in self.queues:
            self.queues.remove(q)
            logger.info("SSE client unsubscribed (%d remaining)", len(self.queues))


@router.get("/stream")
async def sse_stream(request: Request):
    """
    Server-Sent Events endpoint.
    Dashboard opens a persistent connection here and receives
    real-time new_alert / new_flow events as JSON.
    """
    broadcaster: EventBroadcaster = request.app.state.broadcaster

    q = await broadcaster.subscribe()

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    message = await asyncio.wait_for(q.get(), timeout=30)
                    yield message
                except asyncio.TimeoutError:
                    # Send heartbeat to keep connection alive
                    yield {"event": "heartbeat", "data": "{}"}
        except asyncio.CancelledError:
            pass
        finally:
            broadcaster.unsubscribe(q)

    return EventSourceResponse(event_generator())
