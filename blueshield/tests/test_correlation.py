from app.parsers import auth_logs, suricata
from app.services import correlation
from app.services.sample_generator import build_auth_log_lines, build_suricata_alerts


def _all_rows() -> list[dict]:
    """Full synthetic dataset (spec section 13 scenarios) as DB-row dicts."""
    eve_text = "\n".join(__import__("json").dumps(a) for a in build_suricata_alerts())
    auth_text = "\n".join(build_auth_log_lines())

    eve_events = suricata.parse_eve_json(eve_text).events
    auth_events = auth_logs.parse_ssh_auth_log(auth_text, assumed_year=2026).events
    return [e.to_row() for e in (eve_events + auth_events)]


def test_scenario_1_portscan_links_to_ssh_failures():
    incidents = correlation.correlate(_all_rows(), window_minutes=10)
    recon = [i for i in incidents if i.rule_fired == "recon_to_auth_failure"]
    assert len(recon) == 1
    incident = recon[0]
    assert incident.event_rows[0]["src_ip"] == "192.0.2.10"
    assert incident.event_rows[0]["host_id"] == "lab-server-1"
    # scan + 4 ssh failures
    assert len(incident.event_rows) == 5


def test_scenario_2_failures_then_success_links():
    incidents = correlation.correlate(_all_rows(), window_minutes=10)
    brute = [i for i in incidents if i.rule_fired == "brute_force_then_success"]
    assert len(brute) == 1
    incident = brute[0]
    usernames = {e["username"] for e in incident.event_rows}
    assert usernames == {"svc_test"}
    assert len(incident.event_rows) == 4  # 3 failures + 1 success


def test_scenario_3_lone_transfer_is_low_confidence_singleton():
    incidents = correlation.correlate(_all_rows(), window_minutes=10)
    transfer = [i for i in incidents if i.rule_fired == "unusual_outbound_transfer_singleton"]
    assert len(transfer) == 1
    assert transfer[0].confidence == "Low"
    assert len(transfer[0].event_rows) == 1


def test_scenario_4_duplicate_alerts_deduplicate_to_one_with_count_4():
    deduped = correlation.deduplicate(_all_rows())
    dup_group = [e for e in deduped if e["src_ip"] == "198.51.100.10" and e["dest_ip"] == "198.51.100.20"]
    assert len(dup_group) == 1
    assert dup_group[0]["duplicate_count"] == 4


def test_scenario_5_unrelated_events_are_not_linked_together():
    incidents = correlation.correlate(_all_rows(), window_minutes=10)
    # Neither the isolated SMB scan (203.0.113.50->60) nor the later, separate
    # guest-account failures (198.51.100.77, lab-server-7) should produce or
    # join any incident.
    for incident in incidents:
        ips_in_incident = {e["src_ip"] for e in incident.event_rows}
        assert not ({"203.0.113.50", "198.51.100.77"} <= ips_in_incident)
        for e in incident.event_rows:
            assert e["src_ip"] != "203.0.113.50"
            assert e["host_id"] != "lab-server-7"


def test_scenario_6_minimal_evidence_dns_anomaly_creates_no_incident():
    incidents = correlation.correlate(_all_rows(), window_minutes=10)
    for incident in incidents:
        for e in incident.event_rows:
            assert e["event_type"] != "dns_anomaly"


def test_does_not_correlate_on_ip_alone_across_different_hosts():
    """Same src_ip hitting two unrelated hosts should not be merged into one
    incident just because the IP matches.
    """
    rows = [
        {
            "event_id": "evt-a", "timestamp": "2026-01-01T00:00:00+00:00", "event_type": "possible_port_scan",
            "src_ip": "192.0.2.5", "dest_ip": "192.0.2.6", "dest_port": 22, "host_id": "host-a",
            "username": None, "signature": "scan-sig",
        },
        {
            "event_id": "evt-b", "timestamp": "2026-01-01T00:01:00+00:00", "event_type": "ssh_login_failure",
            "src_ip": "192.0.2.5", "dest_ip": "203.0.113.6", "dest_port": 22, "host_id": "host-b",
            "username": "root", "signature": "sshd-fail",
        },
    ]
    incidents = correlation.correlate(rows, window_minutes=10)
    assert incidents == []


def test_window_boundary_outside_window_does_not_link():
    rows = [
        {
            "event_id": "evt-a", "timestamp": "2026-01-01T00:00:00+00:00", "event_type": "possible_port_scan",
            "src_ip": "192.0.2.5", "dest_ip": "192.0.2.6", "dest_port": 22, "host_id": "host-a",
            "username": None, "signature": "scan-sig",
        },
        {
            "event_id": "evt-b", "timestamp": "2026-01-01T00:11:00+00:00", "event_type": "ssh_login_failure",
            "src_ip": "192.0.2.5", "dest_ip": "192.0.2.6", "dest_port": 22, "host_id": "host-a",
            "username": "root", "signature": "sshd-fail",
        },
    ]
    incidents = correlation.correlate(rows, window_minutes=10)
    assert incidents == []


def test_window_boundary_inside_window_links():
    rows = [
        {
            "event_id": "evt-a", "timestamp": "2026-01-01T00:00:00+00:00", "event_type": "possible_port_scan",
            "src_ip": "192.0.2.5", "dest_ip": "192.0.2.6", "dest_port": 22, "host_id": "host-a",
            "username": None, "signature": "scan-sig",
        },
        {
            "event_id": "evt-b", "timestamp": "2026-01-01T00:09:00+00:00", "event_type": "ssh_login_failure",
            "src_ip": "192.0.2.5", "dest_ip": "192.0.2.6", "dest_port": 22, "host_id": "host-a",
            "username": "root", "signature": "sshd-fail",
        },
    ]
    incidents = correlation.correlate(rows, window_minutes=10)
    assert len(incidents) == 1
