import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _bool(name: str, default: str) -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: str) -> int:
    return int(os.getenv(name, default))


DATABASE_PATH = BASE_DIR / os.getenv("DATABASE_PATH", "./data/blueshield.db")

LLM_ENABLED = _bool("LLM_ENABLED", "false")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL_PRIMARY = os.getenv("OLLAMA_MODEL_PRIMARY", "qwen2.5-coder:7b")
OLLAMA_MODEL_SECONDARY = os.getenv("OLLAMA_MODEL_SECONDARY", "deepseek-r1:7b")
OLLAMA_TIMEOUT_SECONDS = _int("OLLAMA_TIMEOUT_SECONDS", "120")

CORRELATION_TIME_WINDOW_MINUTES = _int("CORRELATION_TIME_WINDOW_MINUTES", "10")
DEDUP_WINDOW_SECONDS = _int("DEDUP_WINDOW_SECONDS", "30")

RISK_THRESHOLD_LOW = _int("RISK_THRESHOLD_LOW", "25")
RISK_THRESHOLD_HIGH = _int("RISK_THRESHOLD_HIGH", "50")
RISK_THRESHOLD_CRITICAL = _int("RISK_THRESHOLD_CRITICAL", "75")

MAX_UPLOAD_SIZE_MB = _int("MAX_UPLOAD_SIZE_MB", "10")

# Only localhost/documentation-range hosts are ever allowed for the Ollama client.
ALLOWED_OLLAMA_HOSTS = ("localhost", "127.0.0.1", "::1")
