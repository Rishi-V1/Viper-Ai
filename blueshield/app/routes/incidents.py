import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from app.database.db import get_connection
from app.services import report_builder
from app.services.incident_builder import run_correlation_and_store
from app.services.incident_service import load_incident as _load_incident

router = APIRouter()

VALID_STATUSES = {"New", "Investigating", "Contained", "Closed"}


@router.post("/api/correlation/run")
def run_correlation():
    return run_correlation_and_store()


@router.get("/api/incidents")
def list_incidents(
    status: Optional[str] = None,
    severity_label: Optional[str] = None,
    search: Optional[str] = None,
    sort: str = "severity_desc",
):
    where = []
    params: list = []
    if status is not None:
        where.append("status = ?")
        params.append(status)
    if severity_label is not None:
        where.append("severity_label = ?")
        params.append(severity_label)
    if search:
        where.append("(title LIKE ? OR why_linked LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like])

    where_clause = f"WHERE {' AND '.join(where)}" if where else ""
    order_by = {
        "severity_desc": "severity DESC",
        "severity_asc": "severity ASC",
        "first_seen_desc": "first_seen DESC",
        "first_seen_asc": "first_seen ASC",
    }.get(sort, "severity DESC")

    conn = get_connection()
    try:
        rows = conn.execute(
            f"""
            SELECT incidents.*,
                   (SELECT COUNT(*) FROM incident_events WHERE incident_events.incident_id = incidents.incident_id)
                       AS supporting_event_count
            FROM incidents {where_clause} ORDER BY {order_by}
            """,
            params,
        ).fetchall()
        return {"incidents": [dict(r) for r in rows]}
    finally:
        conn.close()


@router.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    conn = get_connection()
    try:
        incident = _load_incident(conn, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return incident
    finally:
        conn.close()


class StatusUpdate(BaseModel):
    status: str
    note: Optional[str] = None


@router.post("/api/incidents/{incident_id}/status")
def update_status(incident_id: str, update: StatusUpdate):
    if update.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(VALID_STATUSES)}")

    conn = get_connection()
    try:
        existing = conn.execute("SELECT incident_id FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="incident not found")

        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?",
            (update.status, now, incident_id),
        )
        conn.execute(
            "INSERT INTO audit_log (incident_id, action, detail, actor, created_at) VALUES (?, ?, ?, ?, ?)",
            (incident_id, "status_change", json.dumps({"status": update.status, "note": update.note}), "analyst", now),
        )
        conn.commit()
        return {"incident_id": incident_id, "status": update.status}
    finally:
        conn.close()


@router.get("/api/incidents/{incident_id}/report")
def get_report(incident_id: str, fmt: str = "markdown"):
    conn = get_connection()
    try:
        incident = _load_incident(conn, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")

        if fmt == "html":
            content = report_builder.build_html(incident)
            media_type = "text/html"
        else:
            content = report_builder.build_markdown(incident)
            media_type = "text/markdown"

        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO audit_log (incident_id, action, detail, actor, created_at) VALUES (?, ?, ?, ?, ?)",
            (incident_id, "report_exported", json.dumps({"format": fmt}), "analyst", now),
        )
        conn.commit()
        return PlainTextResponse(content=content, media_type=media_type)
    finally:
        conn.close()
