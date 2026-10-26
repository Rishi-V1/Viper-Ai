from fastapi import APIRouter

from app.database.db import get_connection

router = APIRouter()


@router.get("/api/stats/overview")
def overview_stats():
    conn = get_connection()
    try:
        total_events = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
        open_incidents = conn.execute(
            "SELECT COUNT(*) AS c FROM incidents WHERE status != 'Closed'"
        ).fetchone()["c"]
        critical_count = conn.execute(
            "SELECT COUNT(*) AS c FROM incidents WHERE severity_label = 'Critical'"
        ).fetchone()["c"]
        last_ingest_row = conn.execute("SELECT MAX(ingested_at) AS t FROM events").fetchone()

        events_over_time = conn.execute(
            """
            SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) AS bucket, COUNT(*) AS count
            FROM events GROUP BY bucket ORDER BY bucket ASC
            """
        ).fetchall()

        incidents_by_severity = conn.execute(
            "SELECT severity_label, COUNT(*) AS count FROM incidents GROUP BY severity_label"
        ).fetchall()

        top_source_ips = conn.execute(
            """
            SELECT src_ip, COUNT(*) AS count FROM events
            WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY count DESC LIMIT 5
            """
        ).fetchall()

        top_categories = conn.execute(
            "SELECT event_type, COUNT(*) AS count FROM events GROUP BY event_type ORDER BY count DESC LIMIT 5"
        ).fetchall()

        return {
            "total_events": total_events,
            "open_incidents": open_incidents,
            "critical_count": critical_count,
            "last_ingest": last_ingest_row["t"],
            "events_over_time": [dict(r) for r in events_over_time],
            "incidents_by_severity": [dict(r) for r in incidents_by_severity],
            "top_source_ips": [dict(r) for r in top_source_ips],
            "top_categories": [dict(r) for r in top_categories],
        }
    finally:
        conn.close()
