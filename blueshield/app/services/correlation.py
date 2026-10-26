"""Deterministic detection + correlation engine (spec section 9).

Operates on plain event dicts (as returned by sqlite3.Row -> dict, or
NormalizedEvent.to_row()) so it has no dependency on the database and can be
unit tested directly. Never correlates on IP address alone: every rule below
also requires a matching host, account, or event-sequence condition.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.services import settings_store


@dataclass
class CandidateIncident:
    rule_fired: str
    title: str
    why_linked: str
    confidence: str  # Low | Medium | High
    event_rows: list = field(default_factory=list)       # representative (deduplicated) rows
    duplicate_counts: dict = field(default_factory=dict)  # event_id -> duplicate_count


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def _within_window(a: datetime, b: datetime, window_minutes: int) -> bool:
    return abs((b - a).total_seconds()) <= window_minutes * 60


#: Source types whose events can be sensor re-fires of the *same* detection
#: (e.g. an IDS alert reasserting itself for overlapping packets). Auth-log
#: (and other action-log) events are each a discrete real occurrence — two
#: SSH failures for the same account a minute apart are two attempts, not one
#: alert duplicated — so they are never merged here, however similar they look.
DEDUPLICATABLE_SOURCE_TYPES = {"suricata", "firewall"}


def _build_representative(cluster: list[dict]) -> dict:
    rep = dict(cluster[0])
    rep["duplicate_count"] = len(cluster)
    rep["duplicate_event_ids"] = [c["event_id"] for c in cluster]
    rep["first_seen"] = cluster[0]["timestamp"]
    rep["last_seen"] = cluster[-1]["timestamp"]
    return rep


def deduplicate(events: list[dict], dedup_window_seconds: int | None = None) -> list[dict]:
    """Groups sensor-alert events that share (signature, src_ip, dest_ip,
    dest_port, host_id, event_type, username) AND occur within a short
    clustering window into one representative record, preserving the
    underlying count and the first/last-seen time range (spec section 9,
    Phase E). Non-sensor event types (auth logs, etc.) pass through
    unmerged — see DEDUPLICATABLE_SOURCE_TYPES.
    """
    dedup_window_seconds = dedup_window_seconds or settings_store.load()["dedup_window_seconds"]

    dedupable = [e for e in events if e.get("source_type") in DEDUPLICATABLE_SOURCE_TYPES]
    passthrough = [e for e in events if e.get("source_type") not in DEDUPLICATABLE_SOURCE_TYPES]

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for e in dedupable:
        key = (
            e.get("signature"), e.get("src_ip"), e.get("dest_ip"),
            e.get("dest_port"), e.get("host_id"), e.get("event_type"),
            e.get("username"),
        )
        groups[key].append(e)

    deduped = []
    for group in groups.values():
        group = sorted(group, key=lambda e: e["timestamp"])
        cluster = [group[0]]
        for e in group[1:]:
            gap = (_parse_ts(e["timestamp"]) - _parse_ts(cluster[-1]["timestamp"])).total_seconds()
            if gap <= dedup_window_seconds:
                cluster.append(e)
            else:
                deduped.append(_build_representative(cluster))
                cluster = [e]
        deduped.append(_build_representative(cluster))

    for e in passthrough:
        deduped.append(_build_representative([e]))

    return deduped


def rule_recon_to_auth_failure(events: list[dict], window_minutes: int) -> list[CandidateIncident]:
    """Scenario: port-scan alert -> SSH authentication failures from the same
    source, against the same host, within the time window.
    """
    incidents = []
    scans = [e for e in events if e["event_type"] == "possible_port_scan"]
    failures = [e for e in events if e["event_type"] == "ssh_login_failure"]

    for scan in scans:
        scan_ts = _parse_ts(scan["timestamp"])
        related = [
            f for f in failures
            if f["src_ip"] == scan["src_ip"]
            and (f["host_id"] == scan["host_id"] or f["dest_ip"] == scan["dest_ip"])
            and _parse_ts(f["timestamp"]) >= scan_ts
            and _within_window(scan_ts, _parse_ts(f["timestamp"]), window_minutes)
        ]
        if related:
            group = [scan] + related
            incidents.append(CandidateIncident(
                rule_fired="recon_to_auth_failure",
                title=f"Port scan from {scan['src_ip']} followed by SSH failures on {scan['host_id']}",
                why_linked=(
                    f"Source {scan['src_ip']} triggered '{scan['signature']}' against {scan['host_id']} "
                    f"at {scan['timestamp']}, then {len(related)} SSH login failure(s) from the same source "
                    f"against the same host occurred within {window_minutes} minutes. Hypothesis: "
                    "reconnaissance followed by credential-guessing attempts; not confirmed access."
                ),
                confidence="Medium",
                event_rows=group,
                duplicate_counts={e["event_id"]: e.get("duplicate_count", 1) for e in group},
            ))
    return incidents


def rule_brute_force_then_success(events: list[dict], window_minutes: int, min_failures: int = 2) -> list[CandidateIncident]:
    """Scenario: repeated SSH failures for an account/host, then a successful
    login for that same account/host, within the time window.
    """
    incidents = []
    successes = [e for e in events if e["event_type"] == "ssh_login_success"]
    failures = [e for e in events if e["event_type"] == "ssh_login_failure"]

    for success in successes:
        success_ts = _parse_ts(success["timestamp"])
        related_failures = [
            f for f in failures
            if f["src_ip"] == success["src_ip"]
            and f["host_id"] == success["host_id"]
            and f["username"] == success["username"]
            and _parse_ts(f["timestamp"]) <= success_ts
            and _within_window(success_ts, _parse_ts(f["timestamp"]), window_minutes)
        ]
        if len(related_failures) >= min_failures:
            group = related_failures + [success]
            incidents.append(CandidateIncident(
                rule_fired="brute_force_then_success",
                title=f"Successful login for '{success['username']}' on {success['host_id']} after repeated failures",
                why_linked=(
                    f"{len(related_failures)} failed SSH login(s) for account '{success['username']}' from "
                    f"{success['src_ip']} were followed by a successful login to the same account and host "
                    f"within {window_minutes} minutes. This is a hypothesis for investigation — a successful "
                    "login alone does not confirm unauthorized access; verify with the account owner."
                ),
                confidence="Medium",
                event_rows=group,
                duplicate_counts={e["event_id"]: e.get("duplicate_count", 1) for e in group},
            ))
    return incidents


def rule_unusual_outbound_transfer(events: list[dict]) -> list[CandidateIncident]:
    """Scenario: a single high-volume/suspicious outbound-transfer alert with
    no corroborating event. Flagged for review at low confidence rather than
    treated as correlated multi-stage activity.
    """
    incidents = []
    for e in events:
        if e["event_type"] == "unusual_outbound_transfer":
            incidents.append(CandidateIncident(
                rule_fired="unusual_outbound_transfer_singleton",
                title=f"Unusual outbound data volume from {e['host_id']}",
                why_linked=(
                    "A single outbound-transfer alert exceeded the configured volume/signature threshold. "
                    "No corroborating event links this to a confirmed compromise; a scheduled backup or other "
                    "legitimate large transfer is a plausible benign explanation. Analyst validation required "
                    "before treating this as exfiltration."
                ),
                confidence="Low",
                event_rows=[e],
                duplicate_counts={e["event_id"]: e.get("duplicate_count", 1)},
            ))
    return incidents


def correlate(events: list[dict], window_minutes: int | None = None) -> list[CandidateIncident]:
    """Runs deduplication then every correlation rule. `events` is the full
    set of normalized events to consider (typically everything in the
    `events` table, or a bounded recent slice of it).
    """
    window_minutes = window_minutes or settings_store.load()["correlation_time_window_minutes"]
    deduped = deduplicate(events)

    incidents: list[CandidateIncident] = []
    incidents += rule_recon_to_auth_failure(deduped, window_minutes)
    incidents += rule_brute_force_then_success(deduped, window_minutes)
    incidents += rule_unusual_outbound_transfer(deduped)
    return incidents
