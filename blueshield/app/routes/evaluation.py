from fastapi import APIRouter

from app.database.db import get_connection
from app.services import evaluation

router = APIRouter()


@router.get("/api/evaluation")
def get_evaluation():
    result = evaluation.run_evaluation()

    conn = get_connection()
    try:
        result["llm_evaluation"] = evaluation.llm_evaluation_summary(conn)
    finally:
        conn.close()

    return result
