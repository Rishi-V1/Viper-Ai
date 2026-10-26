"""Turns correlation.CandidateIncident objects into persisted incident
records: transparent score, incident_events evidence links, and an audit
log entry per run. Re-running is idempotent — incidents are keyed
deterministically by rule + underlying event IDs, and an analyst's status
is preserved across reruns rather than reset to "New".
"""

import hashlib
import json
from datetime import datetime, timezone

from app.database.db import get_connection, session
from app.services import correlation, mitre_mapping, risk_scoring


def _incident_id(rule_fired: str, event_ids: list[str]) -> str:
    digest = hashlib.sha1((rule_fired + "|" + "|".join(sorted(event_ids))).encode()).hexdigest()[:12]
    return f"inc-{digest}"


def run_correlation_and_store(window_minutes: int | None = None) -> dict:
    conn = get_connection()
    try:
        rows = [dict(r) for r in conn.execute("SELECT * FROM events").fetchall()]
    finally:
        conn.close()

    candidates = correlation.correlate(rows, window_minutes=window_minutes)

    created, updated = 0, 0
    now = datetime.now(timezone.utc).isoformat()

    with session() as conn:
        for candidate in candidates:
            event_ids = [e["event_id"] for e in candidate.event_rows]
            incident_id = _incident_id(candidate.rule_fired, event_ids)
            scoring = risk_scoring.score_incident(candidate)
            timestamps = [e["timestamp"] for e in candidate.event_rows]
            first_seen, last_seen = min(timestamps), max(timestamps)

            existing = conn.execute(
                "SELECT status, created_at FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if existing:
                status, created_at = existing["status"], existing["created_at"]
                updated += 1
            else:
                status, created_at = "New", now
                created += 1

            conn.execute(
                """
                INSERT INTO incidents
                    (incident_id, title, status, severity, severity_label, confidence,
                     rule_fired, why_linked, score_breakdown, first_seen, last_seen,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    severity = excluded.severity,
                    severity_label = excluded.severity_label,
                    confidence = excluded.confidence,
                    why_linked = excluded.why_linked,
                    score_breakdown = excluded.score_breakdown,
                    last_seen = excluded.last_seen,
                    updated_at = excluded.updated_at
                """,
                (
                    incident_id, candidate.title, status, scoring["score"], scoring["label"],
                    candidate.confidence, candidate.rule_fired, candidate.why_linked,
                    json.dumps(scoring["breakdown"]), first_seen, last_seen, created_at, now,
                ),
            )

            conn.execute("DELETE FROM incident_events WHERE incident_id = ?", (incident_id,))
            for e in candidate.event_rows:
                conn.execute(
                    "INSERT INTO incident_events (incident_id, event_id, duplicate_count) VALUES (?, ?, ?)",
                    (incident_id, e["event_id"], e.get("duplicate_count", 1)),
                )

            conn.execute("DELETE FROM attack_mappings WHERE incident_id = ?", (incident_id,))
            for mapping in mitre_mapping.map_incident(candidate):
                conn.execute(
                    """
                    INSERT INTO attack_mappings
                        (incident_id, technique_id, technique_name, rationale,
                         supporting_event_ids, mapping_source, qualification)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id, mapping["technique_id"], mapping["technique_name"],
                        mapping["rationale"], json.dumps(mapping["supporting_event_ids"]),
                        mapping["mapping_source"], mapping["qualification"],
                    ),
                )

        conn.execute(
            "INSERT INTO audit_log (incident_id, action, detail, actor, created_at) VALUES (?, ?, ?, ?, ?)",
            (
                None, "correlation_run",
                json.dumps({"created": created, "updated": updated, "total_candidates": len(candidates)}),
                "system", now,
            ),
        )

    return {"created": created, "updated": updated, "total_candidates": len(candidates)}
