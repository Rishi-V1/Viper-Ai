from app.parsers import auth_logs, suricata


def test_parse_eve_json_valid_alert():
    line = (
        '{"timestamp": "2026-10-26T10:00:00.000000+0000", "flow_id": 1, '
        '"event_type": "alert", "src_ip": "192.0.2.10", "src_port": 53012, '
        '"dest_ip": "192.0.2.20", "dest_port": 22, "proto": "TCP", "host": "lab-server-1", '
        '"alert": {"signature_id": 1, "signature": "ET SCAN Potential SSH Scan", '
        '"category": "Attempted Information Leak", "severity": 2}}'
    )
    result = suricata.parse_eve_json(line)
    assert len(result.events) == 1
    assert not result.errors
    event = result.events[0]
    assert event.event_type == "possible_port_scan"
    assert event.src_ip == "192.0.2.10"
    assert event.timestamp.tzinfo is not None


def test_parse_eve_json_skips_non_alert_events():
    line = '{"event_type": "flow", "src_ip": "192.0.2.10"}'
    result = suricata.parse_eve_json(line)
    assert result.events == []
    assert result.errors == []


def test_parse_eve_json_malformed_json_is_collected_as_error_not_raised():
    text = "{not valid json"
    result = suricata.parse_eve_json(text)
    assert result.events == []
    assert len(result.errors) == 1
    assert "invalid JSON" in result.errors[0].reason


def test_parse_eve_json_missing_required_field_is_collected_as_error():
    line = '{"event_type": "alert", "src_ip": "192.0.2.99"}'  # no timestamp
    result = suricata.parse_eve_json(line)
    assert result.events == []
    assert len(result.errors) == 1


def test_parse_eve_json_invalid_ip_is_collected_as_error():
    line = (
        '{"timestamp": "2026-10-26T10:00:00.000000+0000", "event_type": "alert", '
        '"src_ip": "999.999.999.999", "dest_ip": "192.0.2.20", "host": "h", '
        '"alert": {"signature": "x"}}'
    )
    result = suricata.parse_eve_json(line)
    assert result.events == []
    assert len(result.errors) == 1


def test_parse_ssh_auth_log_failure_and_success():
    text = (
        "Oct 26 10:01:00 lab-server-1 sshd[1000]: Failed password for invalid user root "
        "from 192.0.2.10 port 53013 ssh2\n"
        "Oct 26 10:31:00 lab-server-2 sshd[2010]: Accepted password for svc_test "
        "from 198.51.100.5 port 54030 ssh2"
    )
    result = auth_logs.parse_ssh_auth_log(text, assumed_year=2026)
    assert len(result.events) == 2
    assert not result.errors
    assert result.events[0].event_type == "ssh_login_failure"
    assert result.events[0].username == "root"
    assert result.events[1].event_type == "ssh_login_success"
    assert result.events[1].username == "svc_test"


def test_parse_ssh_auth_log_malformed_line_is_collected_as_error_not_raised():
    text = "this is not a valid sshd line at all"
    result = auth_logs.parse_ssh_auth_log(text, assumed_year=2026)
    assert result.events == []
    assert len(result.errors) == 1


def test_parse_ssh_auth_log_blank_lines_are_ignored():
    text = "\n\n   \n"
    result = auth_logs.parse_ssh_auth_log(text, assumed_year=2026)
    assert result.events == []
    assert result.errors == []
