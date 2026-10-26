"""Runtime-adjustable settings (spec section 12 "Settings" page): time
window, thresholds, scoring weights, Ollama model tag, LLM on/off. Backed by
a small JSON file so changes from the dashboard take effect immediately,
without editing .env or restarting the server. .env/.env.example still
supply the initial defaults.
"""

import json

from app import config

SETTINGS_PATH = config.BASE_DIR / "data" / "settings.json"

DEFAULTS = {
    "correlation_time_window_minutes": config.CORRELATION_TIME_WINDOW_MINUTES,
    "dedup_window_seconds": config.DEDUP_WINDOW_SECONDS,
    "risk_threshold_low": config.RISK_THRESHOLD_LOW,
    "risk_threshold_high": config.RISK_THRESHOLD_HIGH,
    "risk_threshold_critical": config.RISK_THRESHOLD_CRITICAL,
    "severity_points_per_unit": 8,
    "sequence_bonus": 20,
    "llm_enabled": config.LLM_ENABLED,
    "ollama_model_primary": config.OLLAMA_MODEL_PRIMARY,
    "ollama_model_secondary": config.OLLAMA_MODEL_SECONDARY,
}

# Keys the Settings page is allowed to change. Anything else in a POST body
# is ignored rather than silently creating new, unvalidated config keys.
EDITABLE_KEYS = set(DEFAULTS.keys())


def load() -> dict:
    if SETTINGS_PATH.exists():
        try:
            data = json.loads(SETTINGS_PATH.read_text())
        except json.JSONDecodeError:
            data = {}
        return {**DEFAULTS, **{k: v for k, v in data.items() if k in EDITABLE_KEYS}}
    return dict(DEFAULTS)


def save(partial: dict) -> dict:
    current = load()
    current.update({k: v for k, v in partial.items() if k in EDITABLE_KEYS})
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_PATH.write_text(json.dumps(current, indent=2))
    return current
