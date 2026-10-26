def test_health_endpoint(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_ingest_sample_then_list_events(client):
    ingest_result = client.post("/api/ingest/sample").json()
    assert ingest_result["inserted"] > 0

    events = client.get("/api/events").json()
    assert events["total"] == ingest_result["inserted"]


def test_full_flow_ingest_correlate_incident_detail(client):
    client.post("/api/ingest/sample")
    correlation_result = client.post("/api/correlation/run").json()
    assert correlation_result["created"] > 0

    incidents = client.get("/api/incidents").json()["incidents"]
    assert len(incidents) == correlation_result["created"]

    incident_id = incidents[0]["incident_id"]
    detail = client.get(f"/api/incidents/{incident_id}").json()
    assert detail["incident_id"] == incident_id
    assert len(detail["evidence"]) > 0
    assert "score_breakdown" in detail

    # idempotency: re-running correlation must not create new incidents
    rerun = client.post("/api/correlation/run").json()
    assert rerun["created"] == 0
    assert rerun["updated"] == correlation_result["created"]


def test_correlation_run_with_no_events_creates_nothing(client):
    result = client.post("/api/correlation/run").json()
    assert result == {"created": 0, "updated": 0, "total_candidates": 0}


def test_incident_not_found_returns_404(client):
    response = client.get("/api/incidents/inc-does-not-exist")
    assert response.status_code == 404


def test_status_update_rejects_invalid_status(client):
    client.post("/api/ingest/sample")
    client.post("/api/correlation/run")
    incident_id = client.get("/api/incidents").json()["incidents"][0]["incident_id"]

    bad = client.post(f"/api/incidents/{incident_id}/status", json={"status": "Not A Real Status"})
    assert bad.status_code == 400

    good = client.post(f"/api/incidents/{incident_id}/status", json={"status": "Investigating"})
    assert good.status_code == 200
    assert client.get(f"/api/incidents/{incident_id}").json()["status"] == "Investigating"


def test_report_export_markdown_and_html(client):
    client.post("/api/ingest/sample")
    client.post("/api/correlation/run")
    incident_id = client.get("/api/incidents").json()["incidents"][0]["incident_id"]

    md = client.get(f"/api/incidents/{incident_id}/report")
    assert md.status_code == 200
    assert "# Incident Report" in md.text

    html = client.get(f"/api/incidents/{incident_id}/report?fmt=html")
    assert html.status_code == 200
    assert "<html>" in html.text


def test_upload_rejects_disallowed_extension(client):
    response = client.post(
        "/api/ingest/upload",
        files={"file": ("malware.exe", b"not a real log", "application/octet-stream")},
    )
    assert response.status_code == 400


def test_upload_accepts_valid_log_file(client):
    content = (
        "Oct 26 10:01:00 lab-server-x sshd[1]: Failed password for invalid user root "
        "from 192.0.2.50 port 55000 ssh2\n"
    )
    response = client.post("/api/ingest/upload", files={"file": ("custom.log", content, "text/plain")})
    assert response.status_code == 200
    assert response.json()["inserted"] == 1


def test_settings_roundtrip(client):
    defaults = client.get("/api/settings").json()
    assert defaults["llm_enabled"] is False

    updated = client.post("/api/settings", json={"llm_enabled": True, "correlation_time_window_minutes": 15}).json()
    assert updated["llm_enabled"] is True
    assert updated["correlation_time_window_minutes"] == 15

    # confirms it persisted, not just echoed back
    assert client.get("/api/settings").json()["correlation_time_window_minutes"] == 15


def test_analyze_disabled_by_default(client):
    client.post("/api/ingest/sample")
    client.post("/api/correlation/run")
    incident_id = client.get("/api/incidents").json()["incidents"][0]["incident_id"]

    response = client.post(f"/api/incidents/{incident_id}/analyze", json={"model": "primary"})
    assert response.status_code == 200
    assert response.json()["status"] == "disabled"
