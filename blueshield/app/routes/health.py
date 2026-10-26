from datetime import datetime, timezone

from fastapi import APIRouter

from app import config

router = APIRouter()


@router.get("/api/health")
def health():
    return {
        "status": "ok",
        "time": datetime.now(timezone.utc).isoformat(),
        "llm_enabled": config.LLM_ENABLED,
    }
