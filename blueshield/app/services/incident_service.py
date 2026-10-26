"""Shared incident-loading logic used by both the incidents routes and the
LLM-analysis route, so there's one place that assembles an incident's full
evidence set.
"""

import json
import sqlite3
from typing import Optional


def load_incident(conn: sqlite3.Connection, incident_id: str) -> Optional[dict]:
    incident = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    if not incident:
        return None

    events = conn.execute(
        """
        SELECT events.*, incident_events.duplicate_count AS linked_duplicate_count
        FROM incident_events
        JOIN events ON events.event_id = incident_events.event_id
        WHERE incident_events.incident_id = ?
        ORDER BY events.timestamp ASC
        """,
        (incident_id,),
    ).fetchall()

    mappings = conn.execute(
        "SELECT technique_id, technique_name, rationale, supporting_event_ids, mapping_source, qualification "
        "FROM attack_mappings WHERE incident_id = ?",
        (incident_id,),
    ).fetchall()

    analyses = conn.execute(
        "SELECT model_tag, prompt_version, response_json, response_raw, validation_status, latency_ms, created_at "
        "FROM model_analyses WHERE incident_id = ? ORDER BY created_at DESC",
        (incident_id,),
    ).fetchall()

    incident_dict = dict(incident)
    incident_dict["score_breakdown"] = json.loads(incident_dict["score_breakdown"])
    incident_dict["evidence"] = [dict(e) for e in events]
    incident_dict["attack_mappings"] = [
        {**dict(m), "supporting_event_ids": json.loads(m["supporting_event_ids"])} for m in mappings
    ]
    incident_dict["model_analyses"] = [
        {**dict(a), "response_json": json.loads(a["response_json"]) if a["response_json"] else None}
        for a in analyses
    ]
    return incident_dict
