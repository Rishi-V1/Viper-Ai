from app.services import risk_scoring
from app.services.correlation import CandidateIncident


def _candidate(rule_fired, severities, duplicate_counts=None, host_id="lab-server-1"):
    duplicate_counts = duplicate_counts or [1] * len(severities)
    rows = [
        {"event_id": f"evt-{i}", "severity": s, "host_id": host_id, "duplicate_count": d}
        for i, (s, d) in enumerate(zip(severities, duplicate_counts))
    ]
    return CandidateIncident(rule_fired=rule_fired, title="t", why_linked="w", confidence="Medium", event_rows=rows)


def test_severity_label_boundaries():
    assert risk_scoring.severity_label(0) == "Informational"
    assert risk_scoring.severity_label(24) == "Informational"
    assert risk_scoring.severity_label(25) == "Low"
    assert risk_scoring.severity_label(49) == "Low"
    assert risk_scoring.severity_label(50) == "High"
    assert risk_scoring.severity_label(74) == "High"
    assert risk_scoring.severity_label(75) == "Critical"
    assert risk_scoring.severity_label(100) == "Critical"


def test_multi_stage_rule_gets_sequence_bonus_singleton_does_not():
    multi = risk_scoring.score_incident(_candidate("recon_to_auth_failure", [2, 1]))
    singleton = risk_scoring.score_incident(_candidate("unusual_outbound_transfer_singleton", [2]))
    assert multi["breakdown"]["sequence_bonus"] == 20
    assert singleton["breakdown"]["sequence_bonus"] == 0


def test_duplicate_penalty_reduces_score_and_is_capped():
    low_dup = risk_scoring.score_incident(_candidate("recon_to_auth_failure", [2, 2], duplicate_counts=[1, 1]))
    high_dup = risk_scoring.score_incident(_candidate("recon_to_auth_failure", [2, 2], duplicate_counts=[1, 50]))
    assert high_dup["score"] <= low_dup["score"]
    assert high_dup["breakdown"]["duplicate_penalty"] == -risk_scoring.MAX_DUPLICATE_PENALTY


def test_asset_criticality_bonus_uses_known_host_mapping():
    # lab-server-3 is "critical" in data/asset_criticality.json (+25),
    # an unknown host falls back to the documented default (+5).
    critical_host = risk_scoring.score_incident(_candidate("brute_force_then_success", [1], host_id="lab-server-3"))
    unknown_host = risk_scoring.score_incident(_candidate("brute_force_then_success", [1], host_id="totally-unknown-host"))
    assert critical_host["breakdown"]["asset_criticality_bonus"] == 25
    assert unknown_host["breakdown"]["asset_criticality_bonus"] == risk_scoring.ASSET_CRITICALITY_BONUS[
        risk_scoring.DEFAULT_ASSET_CRITICALITY
    ]


def test_score_is_clamped_to_0_100():
    huge = risk_scoring.score_incident(_candidate("recon_to_auth_failure", [100] * 10, host_id="lab-server-3"))
    assert huge["score"] == 100
    tiny = risk_scoring.score_incident(_candidate("unusual_outbound_transfer_singleton", [0], duplicate_counts=[500]))
    assert tiny["score"] == 0


def test_confidence_is_independent_of_score():
    """Severity and confidence must stay separate: a high-severity candidate
    can still carry low confidence, and the scorer must not silently derive
    one from the other.
    """
    candidate = _candidate("recon_to_auth_failure", [3, 3, 3], host_id="lab-server-3")
    candidate.confidence = "Low"
    result = risk_scoring.score_incident(candidate)
    assert result["score"] > 50
    assert candidate.confidence == "Low"
