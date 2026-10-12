"""模拟 SIEM 使用的受控事件与告警数据结构。"""

from datetime import UTC, datetime
from ipaddress import IPv4Address
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

EventType = Literal[
    "SSH_FAILED_LOGIN",
    "PORT_SCAN",
    "PRIVILEGE_ESCALATION",
    "COMMAND_EXECUTION",
    "MALWARE",
]


class SecurityEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: f"EVT-{uuid4().hex[:12].upper()}", max_length=64)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str = Field(default="模拟 SIEM", min_length=1, max_length=100)
    asset_ip: IPv4Address
    event_type: EventType
    severity: Literal["LOW", "MEDIUM", "HIGH"] = "MEDIUM"
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("事件时间必须包含时区")
        return value.astimezone(UTC)


class SecurityAlert(BaseModel):
    alert_id: str = Field(default_factory=lambda: f"ALT-{uuid4().hex[:12].upper()}")
    event_id: str
    asset_ip: IPv4Address
    alert_type: str
    severity: Literal["MEDIUM", "HIGH"]
    reason: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    investigation_id: str | None = None
