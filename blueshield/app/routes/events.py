from typing import Optional

from fastapi import APIRouter, Query

from app.database.db import get_connection

router = APIRouter()


@router.get("/api/events")
def list_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    event_type: Optional[str] = None,
    source_type: Optional[str] = None,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    host_id: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    search: Optional[str] = Query(None, description="substring match on signature or username"),
):
    where = []
    params: list = []

    def eq_filter(column: str, value: Optional[str]):
        if value is not None:
            where.append(f"{column} = ?")
            params.append(value)

    eq_filter("event_type", event_type)
    eq_filter("source_type", source_type)
    eq_filter("src_ip", src_ip)
    eq_filter("dest_ip", dest_ip)
    eq_filter("host_id", host_id)

    if start_time is not None:
        where.append("timestamp >= ?")
        params.append(start_time)
    if end_time is not None:
        where.append("timestamp <= ?")
        params.append(end_time)
    if search:
        where.append("(signature LIKE ? OR username LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like])

    where_clause = f"WHERE {' AND '.join(where)}" if where else ""

    conn = get_connection()
    try:
        total = conn.execute(f"SELECT COUNT(*) AS c FROM events {where_clause}", params).fetchone()["c"]
        rows = conn.execute(
            f"SELECT * FROM events {where_clause} ORDER BY timestamp ASC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "events": [dict(row) for row in rows],
        }
    finally:
        conn.close()
