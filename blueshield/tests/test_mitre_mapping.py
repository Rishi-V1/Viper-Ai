from app.services import mitre_mapping
from app.services.correlation import CandidateIncident


def test_recon_to_auth_failure_maps_to_scanning_and_brute_force():
    candidate = CandidateIncident(
        rule_fired="recon_to_auth_failure",
        title="t", why_linked="w", confidence="Medium",
        event_rows=[
            {"event_id": "evt-scan", "event_type": "possible_port_scan"},
            {"event_id": "evt-fail1", "event_type": "ssh_login_failure"},
            {"event_id": "evt-fail2", "event_type": "ssh_login_failure"},
        ],
    )
    mappings = mitre_mapping.map_incident(candidate)
    ids = {m["technique_id"] for m in mappings}
    assert ids == {"T1595", "T1110"}

    scan_mapping = next(m for m in mappings if m["technique_id"] == "T1595")
    assert scan_mapping["supporting_event_ids"] == ["evt-scan"]

    brute_mapping = next(m for m in mappings if m["technique_id"] == "T1110")
    assert set(brute_mapping["supporting_event_ids"]) == {"evt-fail1", "evt-fail2"}


def test_singleton_transfer_maps_with_low_confidence_qualification():
    candidate = CandidateIncident(
        rule_fired="unusual_outbound_transfer_singleton",
        title="t", why_linked="w", confidence="Low",
        event_rows=[{"event_id": "evt-transfer", "event_type": "unusual_outbound_transfer"}],
    )
    mappings = mitre_mapping.map_incident(candidate)
    assert len(mappings) == 1
    assert mappings[0]["technique_id"] == "T1041"
    assert "unconfirmed" in mappings[0]["qualification"]


def test_unmapped_rule_produces_no_mapping():
    candidate = CandidateIncident(
        rule_fired="some_future_rule_not_in_mitre_table",
        title="t", why_linked="w", confidence="Low",
        event_rows=[{"event_id": "evt-x", "event_type": "dns_anomaly"}],
    )
    assert mitre_mapping.map_incident(candidate) == []


def test_every_mapping_cites_only_event_ids_actually_in_the_incident():
    candidate = CandidateIncident(
        rule_fired="brute_force_then_success",
        title="t", why_linked="w", confidence="Medium",
        event_rows=[
            {"event_id": "evt-fail1", "event_type": "ssh_login_failure"},
            {"event_id": "evt-fail2", "event_type": "ssh_login_failure"},
            {"event_id": "evt-success", "event_type": "ssh_login_success"},
        ],
    )
    known_ids = {e["event_id"] for e in candidate.event_rows}
    for mapping in mitre_mapping.map_incident(candidate):
        assert set(mapping["supporting_event_ids"]) <= known_ids
