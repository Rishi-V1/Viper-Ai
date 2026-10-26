"""Transparent risk scoring (spec section 10).

risk_score = event_severity_points + sequence_bonus + asset_criticality_bonus
             - duplicate_penalty, clamped to 0-100.

Weights below are project-defined starting points to be tuned against the
labelled test dataset, not an industry standard. Severity (potential impact)
is kept separate from confidence (how strongly the evidence supports the
hypothesis) — confidence comes from the correlation rule that fired, not
from this score.
"""

import json

from app import config
from app.services import settings_store

# Fallback weights if settings.json has no overrides yet; the authoritative
# values at runtime always come through settings_store.load().
SEVERITY_POINTS_PER_UNIT = settings_store.DEFAULTS["severity_points_per_unit"]
SEQUENCE_BONUS = settings_store.DEFAULTS["sequence_bonus"]
DUPLICATE_PENALTY_PER_EXTRA = 2
MAX_DUPLICATE_PENALTY = 20

ASSET_CRITICALITY_BONUS = {"low": 0, "medium": 5, "high": 15, "critical": 25}
DEFAULT_ASSET_CRITICALITY = "medium"

#: Rules that represent a multi-stage event sequence (vs. a single-alert flag).
MULTI_STAGE_RULES = {"recon_to_auth_failure", "brute_force_then_success"}

ASSET_CRITICALITY_PATH = config.BASE_DIR / "data" / "asset_criticality.json"


def _load_asset_criticality() -> dict:
    if ASSET_CRITICALITY_PATH.exists():
        return json.loads(ASSET_CRITICALITY_PATH.read_text())
    return {}


def severity_label(score: int, settings: dict | None = None) -> str:
    """Project-defined categories (section 10), not official thresholds.
    Boundaries come from settings_store so the Settings page can tune them.
    """
    settings = settings or settings_store.load()
    low, high, critical = (
        settings["risk_threshold_low"], settings["risk_threshold_high"], settings["risk_threshold_critical"],
    )
    if score < low:
        return "Informational"
    if score < high:
        return "Low"
    if score < critical:
        return "High"
    return "Critical"


def score_incident(candidate) -> dict:
    """Scores a correlation.CandidateIncident. Returns
    {"score": int, "label": str, "breakdown": {...}} with every factor
    visible so the dashboard can show *why* the score is what it is.
    """
    settings = settings_store.load()
    criticality_map = _load_asset_criticality()

    severity_points_per_unit = settings["severity_points_per_unit"]
    event_severity_points = sum(e.get("severity", 0) or 0 for e in candidate.event_rows) * severity_points_per_unit

    sequence_bonus = settings["sequence_bonus"] if candidate.rule_fired in MULTI_STAGE_RULES else 0

    host_ids = sorted({e.get("host_id") for e in candidate.event_rows if e.get("host_id")})
    asset_criticality_bonus = sum(
        ASSET_CRITICALITY_BONUS.get(
            criticality_map.get(host_id, DEFAULT_ASSET_CRITICALITY),
            ASSET_CRITICALITY_BONUS[DEFAULT_ASSET_CRITICALITY],
        )
        for host_id in host_ids
    )

    extra_duplicates = sum(max(0, (e.get("duplicate_count") or 1) - 1) for e in candidate.event_rows)
    duplicate_penalty = min(extra_duplicates * DUPLICATE_PENALTY_PER_EXTRA, MAX_DUPLICATE_PENALTY)

    raw_total = event_severity_points + sequence_bonus + asset_criticality_bonus - duplicate_penalty
    score = max(0, min(100, raw_total))

    breakdown = {
        "event_severity_points": event_severity_points,
        "sequence_bonus": sequence_bonus,
        "asset_criticality_bonus": asset_criticality_bonus,
        "duplicate_penalty": -duplicate_penalty,
        "assets_considered": host_ids,
        "raw_total_before_clamp": raw_total,
        "clamped_score": score,
    }

    return {"score": score, "label": severity_label(score, settings), "breakdown": breakdown}
