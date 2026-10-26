import json

from app import config
from app.services import ollama_client

VALID_RESPONSE = json.dumps({
    "summary": "SSH brute-force hypothesis",
    "observed_evidence": [{"event_id": "evt-1", "description": "port scan"}, {"event_id": "evt-2", "description": "ssh failure"}],
    "possible_attack_sequence": "scan then credential guessing",
    "confidence": "Medium",
    "alternative_explanations": "legitimate admin troubleshooting",
    "potential_impact": "unauthorized access if successful",
    "recommended_investigation_steps": ["check account owner", "review auth logs"],
    "suggested_containment_options": ["block source IP pending approval"],
    "missing_evidence_and_limitations": "no endpoint telemetry available",
})


def _incident():
    return {
        "title": "t", "rule_fired": "recon_to_auth_failure", "severity": 80,
        "severity_label": "Critical", "confidence": "Medium",
        "evidence": [
            {"event_id": "evt-1", "timestamp": "2026-01-01T00:00:00+00:00", "event_type": "possible_port_scan",
             "src_ip": "192.0.2.1", "dest_ip": "192.0.2.2", "host_id": "h", "username": None, "signature": "s"},
            {"event_id": "evt-2", "timestamp": "2026-01-01T00:01:00+00:00", "event_type": "ssh_login_failure",
             "src_ip": "192.0.2.1", "dest_ip": None, "host_id": "h", "username": "root", "signature": "s2"},
        ],
    }


def test_build_prompt_delimits_evidence_and_includes_event_ids():
    prompt, version = ollama_client.build_prompt(_incident())
    assert "<<<EVIDENCE>>>" in prompt
    assert "<<<END_EVIDENCE>>>" in prompt
    assert "evt-1" in prompt
    assert "evt-2" in prompt
    assert version == ollama_client.PROMPT_VERSION


def test_validate_response_valid():
    result = ollama_client.validate_response(VALID_RESPONSE, known_event_ids={"evt-1", "evt-2"})
    assert result["status"] == "valid"
    assert result["parsed"]["summary"] == "SSH brute-force hypothesis"


def test_validate_response_invalid_json():
    result = ollama_client.validate_response("not json at all {", known_event_ids={"evt-1"})
    assert result["status"] == "invalid_json"
    assert result["parsed"] is None


def test_validate_response_missing_required_key():
    broken = json.loads(VALID_RESPONSE)
    del broken["missing_evidence_and_limitations"]
    result = ollama_client.validate_response(json.dumps(broken), known_event_ids={"evt-1", "evt-2"})
    assert result["status"] == "invalid_schema"


def test_validate_response_rejects_hallucinated_event_id():
    hallucinated = json.loads(VALID_RESPONSE)
    hallucinated["observed_evidence"].append({"event_id": "evt-does-not-exist", "description": "made up"})
    result = ollama_client.validate_response(json.dumps(hallucinated), known_event_ids={"evt-1", "evt-2"})
    assert result["status"] == "unknown_event_id"


def test_validate_response_strips_markdown_code_fences():
    fenced = f"```json\n{VALID_RESPONSE}\n```"
    result = ollama_client.validate_response(fenced, known_event_ids={"evt-1", "evt-2"})
    assert result["status"] == "valid"


def test_call_model_fails_gracefully_on_connection_error(monkeypatch):
    # Nothing is listening on this port; call_model must not raise.
    monkeypatch.setattr(config, "OLLAMA_BASE_URL", "http://127.0.0.1:1")
    result = ollama_client.call_model("some-model", "prompt text", timeout_seconds=1)
    assert result["error"] is not None
    assert result["raw_text"] is None


def test_call_model_refuses_non_localhost_host(monkeypatch):
    monkeypatch.setattr(config, "OLLAMA_BASE_URL", "http://example.com:11434")
    result = ollama_client.call_model("some-model", "prompt text")
    assert result["error"] is not None
    assert "localhost" in result["error"]


def test_analyze_incident_surfaces_connection_error_without_raising(monkeypatch):
    monkeypatch.setattr(config, "OLLAMA_BASE_URL", "http://127.0.0.1:1")
    monkeypatch.setattr(config, "OLLAMA_TIMEOUT_SECONDS", 1)
    result = ollama_client.analyze_incident(_incident(), "some-model")
    assert result["validation_status"] == "error"
    assert result["response_json"] is None
