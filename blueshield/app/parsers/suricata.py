import json
from datetime import datetime
from typing import NamedTuple
from uuid import uuid4

from pydantic import ValidationError

from app.schemas.event import NormalizedEvent


class ParseError(NamedTuple):
    line_number: int
    raw: str
    reason: str


class ParseResult(NamedTuple):
    events: list[NormalizedEvent]
    errors: list[ParseError]


def _parse_timestamp(raw: str) -> datetime:
    # Suricata eve.json timestamps look like "2026-10-26T10:00:00.000000+0000".
    return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%f%z")


def _classify_signature(signature: str) -> str:
    sig = signature.lower()
    if "scan" in sig:
        return "possible_port_scan"
    if "dns" in sig:
        return "dns_anomaly"
    if "exfiltration" in sig or "data transfer" in sig:
        return "unusual_outbound_transfer"
    return "suricata_alert"


def parse_eve_json(text: str, source_label: str = "suricata.eve.json") -> ParseResult:
    """Parses a Suricata eve.json file (one JSON object per line). Only
    event_type=="alert" lines are treated as detections in this version;
    conn/dns telemetry (Zeek-style) is a later milestone. Malformed lines are
    collected as errors and skipped rather than raising.
    """
    events: list[NormalizedEvent] = []
    errors: list[ParseError] = []

    for i, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue

        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(ParseError(i, line, f"invalid JSON: {exc}"))
            continue

        if obj.get("event_type") != "alert":
            continue

        alert = obj.get("alert") or {}
        try:
            event = NormalizedEvent(
                event_id=f"evt-{uuid4().hex[:12]}",
                timestamp=_parse_timestamp(obj["timestamp"]),
                source_type="suricata",
                event_type=_classify_signature(alert.get("signature", "")),
                src_ip=obj.get("src_ip"),
                src_port=obj.get("src_port"),
                dest_ip=obj.get("dest_ip"),
                dest_port=obj.get("dest_port"),
                protocol=obj.get("proto"),
                severity=alert.get("severity", 0),
                signature=alert.get("signature"),
                host_id=obj.get("host"),
                username=None,
                evidence=f"Suricata alert, category={alert.get('category', 'unknown')}",
                raw_reference=f"{source_label}:line {i}, flow_id={obj.get('flow_id')}",
            )
        except (KeyError, ValueError, ValidationError) as exc:
            errors.append(ParseError(i, line, f"missing/invalid field: {exc}"))
            continue

        events.append(event)

    return ParseResult(events, errors)
