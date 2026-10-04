"""Pydantic request schemas with strict validation at the API boundary."""

from __future__ import annotations

import ipaddress
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

Protocol = Literal["TCP", "UDP", "ICMP"]
AlertStatus = Literal["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]


class FlowIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    flow_id: str = Field(default_factory=lambda: f"FLOW-{uuid4().hex[:12].upper()}", min_length=3, max_length=80)
    timestamp: str | None = None
    source_ip: str
    destination_ip: str
    source_port: int = Field(default=0, ge=0, le=65535)
    destination_port: int = Field(default=0, ge=0, le=65535)
    protocol: Protocol = "TCP"
    packet_count: float = Field(default=0, ge=0, le=1e12)
    byte_count: float = Field(default=0, ge=0, le=1e15)
    duration_seconds: float = Field(default=0, ge=0, le=1e9)
    connection_count: float = Field(default=1, ge=0, le=1e12)
    failed_connection_count: float = Field(default=0, ge=0, le=1e12)
    syn_count: float = Field(default=0, ge=0, le=1e12)
    rst_count: float = Field(default=0, ge=0, le=1e12)
    average_packet_size: float = Field(default=0, ge=0, le=1e12)
    unique_destination_ports: int = Field(default=1, ge=0, le=65536)
    unique_destination_ips: int = Field(default=1, ge=0, le=1_000_000)
    label: str | None = Field(default=None, max_length=30)
    scenario_type: str | None = Field(default=None, max_length=80)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("must be a valid IPv4 or IPv6 address") from exc

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return value
        from ids.timeutils import normalize_timestamp
        return normalize_timestamp(value)


class AlertStatusUpdate(BaseModel):
    status: AlertStatus
    note: str | None = Field(default=None, max_length=2000)
    resolution_notes: str | None = Field(default=None, max_length=4000)
    actor: str = Field(default="analyst", min_length=1, max_length=80)


class AnalystNoteIn(BaseModel):
    note: str = Field(min_length=1, max_length=2000)
    author: str = Field(default="analyst", min_length=1, max_length=80)


class RuleUpdate(BaseModel):
    enabled: bool | None = None
    threshold: float | None = Field(default=None, ge=0, le=1e15)


class ReplayRequest(BaseModel):
    mode: Literal["normal", "mixed"] = "mixed"
    count: int = Field(default=24, ge=1, le=200)
    seed: int | None = None
