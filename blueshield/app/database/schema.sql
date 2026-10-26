-- BlueShield normalized event / incident schema (spec section 8).

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,              -- UTC ISO-8601
    source_type TEXT NOT NULL,            -- suricata | zeek | auth_log | firewall
    event_type TEXT NOT NULL,
    src_ip TEXT,
    src_port INTEGER,
    dest_ip TEXT,
    dest_port INTEGER,
    protocol TEXT,
    severity INTEGER NOT NULL DEFAULT 0,
    signature TEXT,
    host_id TEXT,
    username TEXT,
    evidence TEXT,
    raw_reference TEXT,                   -- pointer back to the original raw line/object
    ingested_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events (src_ip);
CREATE INDEX IF NOT EXISTS idx_events_dest_ip ON events (dest_ip);
CREATE INDEX IF NOT EXISTS idx_events_host ON events (host_id);
CREATE INDEX IF NOT EXISTS idx_events_username ON events (username);
CREATE INDEX IF NOT EXISTS idx_events_type ON events (event_type);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New',   -- New | Investigating | Contained | Closed
    severity INTEGER NOT NULL,            -- 0-100 risk_score
    severity_label TEXT NOT NULL,         -- Informational | Low | High | Critical
    confidence TEXT NOT NULL,             -- Low | Medium | High
    rule_fired TEXT NOT NULL,
    why_linked TEXT NOT NULL,             -- human-readable correlation rationale
    score_breakdown TEXT NOT NULL,        -- JSON: factor -> points
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity);

CREATE TABLE IF NOT EXISTS incident_events (
    incident_id TEXT NOT NULL REFERENCES incidents (incident_id),
    event_id TEXT NOT NULL REFERENCES events (event_id),
    duplicate_count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (incident_id, event_id)
);

CREATE TABLE IF NOT EXISTS attack_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents (incident_id),
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    rationale TEXT NOT NULL,
    supporting_event_ids TEXT NOT NULL,   -- JSON array
    mapping_source TEXT NOT NULL,
    qualification TEXT NOT NULL           -- e.g. "possible", "likely"
);

CREATE TABLE IF NOT EXISTS model_analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents (incident_id),
    model_tag TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    response_json TEXT,
    response_raw TEXT,
    validation_status TEXT NOT NULL,      -- valid | invalid_json | invalid_schema | unknown_event_id | error | disabled
    latency_ms INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT,
    action TEXT NOT NULL,                 -- status_change | note_added | report_exported | ingest | analysis_requested
    detail TEXT,
    actor TEXT NOT NULL DEFAULT 'analyst',
    created_at TEXT NOT NULL
);
