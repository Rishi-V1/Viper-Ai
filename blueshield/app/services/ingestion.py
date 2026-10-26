from datetime import datetime, timezone
from pathlib import Path

from app.database.db import session
from app.parsers import auth_logs, suricata
from app.schemas.event import NormalizedEvent


def insert_events(events: list[NormalizedEvent]) -> int:
    inserted = 0
    now = datetime.now(timezone.utc).isoformat()
    with session() as conn:
        for e in events:
            row = e.to_row()
            conn.execute(
                """
                INSERT OR IGNORE INTO events
                    (event_id, timestamp, source_type, event_type, src_ip, src_port,
                     dest_ip, dest_port, protocol, severity, signature, host_id,
                     username, evidence, raw_reference, ingested_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["event_id"], row["timestamp"], row["source_type"], row["event_type"],
                    row["src_ip"], row["src_port"], row["dest_ip"], row["dest_port"],
                    row["protocol"], row["severity"], row["signature"], row["host_id"],
                    row["username"], row["evidence"], row["raw_reference"], now,
                ),
            )
            inserted += 1
    return inserted


def ingest_demo_data(samples_dir: Path) -> dict:
    """Parses and stores the bundled synthetic eve.json + auth.log sample
    files. Used by the "Load demo data" ingest-page action and by
    POST /api/ingest/sample.
    """
    eve_text = (samples_dir / "eve.json").read_text()
    auth_text = (samples_dir / "auth.log").read_text()

    eve_result = suricata.parse_eve_json(eve_text)
    auth_result = auth_logs.parse_ssh_auth_log(auth_text, assumed_year=2026)

    inserted = insert_events(eve_result.events + auth_result.events)

    return {
        "inserted": inserted,
        "sources": {
            "eve_json": {"parsed": len(eve_result.events), "errors": len(eve_result.errors)},
            "auth_log": {"parsed": len(auth_result.events), "errors": len(auth_result.errors)},
        },
        "parse_errors": [e._asdict() for e in (eve_result.errors + auth_result.errors)],
    }


def ingest_uploaded_file(filename: str, text: str) -> dict:
    """Parses an uploaded file by guessing its format from content/extension.
    Suricata eve.json is JSON-lines; auth logs are syslog-style text.
    """
    stripped = text.lstrip()
    if stripped.startswith("{"):
        result = suricata.parse_eve_json(text, source_label=filename)
    else:
        result = auth_logs.parse_ssh_auth_log(text, assumed_year=datetime.now(timezone.utc).year, source_label=filename)

    inserted = insert_events(result.events)
    return {
        "inserted": inserted,
        "parsed": len(result.events),
        "errors": len(result.errors),
        "parse_errors": [e._asdict() for e in result.errors],
    }
