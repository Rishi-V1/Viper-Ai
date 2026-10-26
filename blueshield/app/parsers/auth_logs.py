import re
from datetime import datetime, timezone
from typing import NamedTuple
from uuid import uuid4

from pydantic import ValidationError

from app.schemas.event import NormalizedEvent

# e.g. "Oct 26 10:01:00 lab-server-1 sshd[1000]: Failed password for invalid user root from 192.0.2.10 port 53013 ssh2"
SSH_LINE_RE = re.compile(
    r"^(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d*)\]:\s+"
    r"(?P<kind>Failed password for invalid user|Accepted password for)\s+"
    r"(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<port>\d+)\s+ssh2\s*$"
)


class ParseError(NamedTuple):
    line_number: int
    raw: str
    reason: str


class ParseResult(NamedTuple):
    events: list[NormalizedEvent]
    errors: list[ParseError]


def parse_ssh_auth_log(text: str, assumed_year: int, source_label: str = "auth.log") -> ParseResult:
    """Parses syslog-style sshd authentication lines. Syslog timestamps carry
    no year, so the caller must supply one (real deployments should take it
    from file mtime or collector metadata, not assume the current year).
    Lines that don't match the expected format are collected as errors and
    skipped rather than raising.
    """
    events: list[NormalizedEvent] = []
    errors: list[ParseError] = []

    for i, line in enumerate(text.splitlines(), start=1):
        raw = line.rstrip()
        if not raw.strip():
            continue

        match = SSH_LINE_RE.match(raw)
        if not match:
            errors.append(ParseError(i, raw, "line does not match expected sshd auth format"))
            continue

        try:
            ts_naive = datetime.strptime(f"{assumed_year} {match['ts']}", "%Y %b %d %H:%M:%S")
            ts = ts_naive.replace(tzinfo=timezone.utc)
            is_success = match["kind"].startswith("Accepted")
            event = NormalizedEvent(
                event_id=f"evt-{uuid4().hex[:12]}",
                timestamp=ts,
                source_type="auth_log",
                event_type="ssh_login_success" if is_success else "ssh_login_failure",
                src_ip=match["src_ip"],
                src_port=int(match["port"]),
                dest_ip=None,
                dest_port=22,
                protocol="TCP",
                severity=3 if is_success else 1,
                signature=f"sshd: {match['kind']}",
                host_id=match["host"],
                username=match["user"],
                evidence="Synthetic SSH authentication log line.",
                raw_reference=f"{source_label}:line {i}",
            )
        except (ValueError, ValidationError) as exc:
            errors.append(ParseError(i, raw, f"missing/invalid field: {exc}"))
            continue

        events.append(event)

    return ParseResult(events, errors)
