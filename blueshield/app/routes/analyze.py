"""POST /api/incidents/{id}/analyze — LLM-assisted draft analysis.

Works fully with the LLM disabled (returns a clean "disabled" response, per
spec section 21's "project depends on a single model" mitigation). When
enabled, every analysis is stored with its model tag, prompt version,
latency, and validation status for reproducibility (spec section 7 step 7),
and the dashboard always labels the result "AI-generated, requires analyst
review."
"""

import json
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.database.db import get_connection, session
from app.services import ollama_client, settings_store
from app.services.incident_service import load_incident

router = APIRouter()


class AnalyzeRequest(BaseModel):
    model: str = "primary"  # "primary" or "secondary"


@router.post("/api/incidents/{incident_id}/analyze")
def analyze_incident(incident_id: str, request: AnalyzeRequest):
    conn = get_connection()
    try:
        incident = load_incident(conn, incident_id)
    finally:
        conn.close()

    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")

    settings = settings_store.load()
    if not settings["llm_enabled"]:
        return {
            "status": "disabled",
            "message": "LLM analysis is disabled (Settings page toggle / LLM_ENABLED=false). "
                       "The dashboard and correlation engine work fully without it.",
        }

    if request.model not in ("primary", "secondary"):
        raise HTTPException(status_code=400, detail="model must be 'primary' or 'secondary'")
    model_tag = settings["ollama_model_primary"] if request.model == "primary" else settings["ollama_model_secondary"]

    result = ollama_client.analyze_incident(incident, model_tag)

    now = datetime.now(timezone.utc).isoformat()
    with session() as conn:
        conn.execute(
            """
            INSERT INTO model_analyses
                (incident_id, model_tag, prompt_version, response_json, response_raw,
                 validation_status, latency_ms, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id, result["model_tag"], result["prompt_version"],
                json.dumps(result["response_json"]) if result["response_json"] is not None else None,
                result["response_raw"], result["validation_status"], result["latency_ms"], now,
            ),
        )
        conn.execute(
            "INSERT INTO audit_log (incident_id, action, detail, actor, created_at) VALUES (?, ?, ?, ?, ?)",
            (
                incident_id, "analysis_requested",
                json.dumps({"model_tag": result["model_tag"], "validation_status": result["validation_status"]}),
                "analyst", now,
            ),
        )

    return {
        "status": result["validation_status"],
        "ai_generated_disclaimer": "AI-generated, requires analyst review",
        "model_tag": result["model_tag"],
        "prompt_version": result["prompt_version"],
        "latency_ms": result["latency_ms"],
        "response": result["response_json"],
        "raw_response": result["response_raw"] if result["response_json"] is None else None,
        "error": result.get("error"),
    }
