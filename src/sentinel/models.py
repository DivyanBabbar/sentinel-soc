from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    timestamp: datetime
    event_type: Literal[
        "login_failed",
        "login_success",
        "privilege_change",
        "api_call",
        "malware_detected",
        "cloud_policy_change",
        "data_access",
    ]
    actor: str = Field(min_length=1, max_length=180)
    source_ip: str | None = Field(default=None, max_length=64)
    resource: str = Field(default="", max_length=300)
    action: str = Field(default="", max_length=200)
    outcome: Literal["success", "failure", "blocked", "unknown"] = "unknown"
    severity: Literal["low", "medium", "high", "critical"] = "low"
    details: str = Field(default="", max_length=2000)


class Incident(BaseModel):
    incident_id: str
    actor: str
    risk_score: int
    severity: Literal["low", "medium", "high", "critical"]
    status: Literal["open", "contained", "closed"] = "open"
    summary: str
    findings: list[str]
    events: list[SecurityEvent]
    recommended_action: Literal["review", "block_ip", "disable_account"]
    containment_status: Literal["not_approved", "approved", "simulated"] = "not_approved"
