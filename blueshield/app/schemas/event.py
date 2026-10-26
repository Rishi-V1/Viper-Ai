from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Optional

from pydantic import BaseModel, field_validator


class NormalizedEvent(BaseModel):
    """Common event schema (spec section 8). Every parser must produce this."""

    event_id: str
    timestamp: datetime
    source_type: str
    event_type: str
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    severity: int = 0
    signature: Optional[str] = None
    host_id: Optional[str] = None
    username: Optional[str] = None
    evidence: Optional[str] = None
    raw_reference: Optional[str] = None

    @field_validator("timestamp")
    @classmethod
    def _timestamp_must_be_tz_aware_and_stored_as_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        return v.astimezone(timezone.utc)

    @field_validator("src_ip", "dest_ip")
    @classmethod
    def _validate_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        ip_address(v)  # raises ValueError if not a valid IPv4/IPv6 address
        return v

    @field_validator("src_port", "dest_port")
    @classmethod
    def _validate_port(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and not (0 <= v <= 65535):
            raise ValueError(f"port out of range: {v}")
        return v

    def to_row(self) -> dict:
        """Dict form used for DB storage and for the correlation engine, with
        `timestamp` as an ISO-8601 string (matching what comes back out of
        SQLite) rather than a datetime object.
        """
        data = self.model_dump()
        data["timestamp"] = self.timestamp.isoformat()
        return data
