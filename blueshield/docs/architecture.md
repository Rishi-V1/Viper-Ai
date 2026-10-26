# BlueShield Architecture

## Design principle

Deterministic Python logic does all detection, correlation, and scoring.
The local LLM (Ollama) only drafts human-readable explanations and
investigation guidance from evidence the deterministic engine already
produced — it never decides on its own that an attack occurred, and the
app works fully with it disabled. Every incident is traceable back to the
specific normalized events and the rule that linked them.

## Component diagram

```text
 Suricata eve.json / SSH auth.log (sample or uploaded)
                    |
            app/parsers/*.py
      (suricata.py, auth_logs.py; zeek.py stubbed)
                    |
        app/schemas/event.py (NormalizedEvent)
     validates: timestamp->UTC, IP format, port range
                    |
          app/services/ingestion.py
                    |
        SQLite: events table (app/database/schema.sql)
                    |
        app/services/correlation.py
   Phase A-E: dedup (sensor alerts only) -> correlation
   rules (recon->auth-failure, brute-force->success,
   lone-transfer flag) -> CandidateIncident list
                    |
       +------------+-------------+
       |            |             |
 risk_scoring.py  mitre_mapping  incident_builder.py
 (0-100 score,    .py (evidence-  (persists incidents,
 severity/conf.   gated ATT&CK    incident_events,
 separate)        technique IDs)  attack_mappings;
       |            |             idempotent reruns)
       +------------+-------------+
                    |
     SQLite: incidents, incident_events,
             attack_mappings, audit_log
                    |
          app/routes/*.py (FastAPI REST API)
                    |          \
          Dashboard (Jinja2 +   ollama_client.py
          Bootstrap + Chart.js)  -> http://localhost:11434
                                  (only on analyst request,
                                   never automatic)
                    |
         model_analyses table (model tag, prompt
         version, latency, validation status —
         every AI output is reproducible/traceable)
```

## Why these choices

- **SQLite, not a bigger DB**: single-file, zero setup, matches "controlled
  lab / sample dataset" scope (spec section 6).
- **Server-rendered dashboard (Jinja2 + vanilla JS + Chart.js)**: no build
  step, runs with `uvicorn app.main:app --reload` and nothing else.
- **Settings stored in `data/settings.json`, not just `.env`**: the
  Settings page (time window, thresholds, scoring weights, LLM on/off) can
  change runtime behavior immediately, without a restart — `.env` still
  supplies the initial defaults.
- **Dedup scoped to sensor-alert sources only** (`app/services/
  correlation.py`): auth-log login attempts are each a discrete real
  event, never collapsed as "duplicate alerts," while re-fired IDS alerts
  for the same detection are.
- **Correlation never keys on IP alone**: every rule also requires a
  matching host, account, or event-sequence condition (spec section 9).
- **MITRE mappings are evidence-gated**: `mitre_mapping.py` only emits a
  technique when a specific event in the incident justifies it, and always
  cites which event IDs support it.
- **Ollama client fails closed, never raises**: a timeout, connection
  refusal, or malformed response becomes a stored `validation_status` of
  `error`/`invalid_json`/`invalid_schema`/`unknown_event_id`; the
  dashboard and correlation engine never depend on it being reachable.

## Data flow for one request ("Load demo data" -> incident)

1. `POST /api/ingest/sample` reads `data/samples/eve.json` + `auth.log`.
2. `app/parsers/suricata.py` / `auth_logs.py` normalize each line into a
   `NormalizedEvent`, validating as they go; malformed lines are collected
   as errors, never raised.
3. Valid events are stored in `events`.
4. `POST /api/correlation/run` loads all events, deduplicates sensor
   alerts, runs the three correlation rules, scores each resulting
   candidate, maps ATT&CK techniques, and upserts `incidents` /
   `incident_events` / `attack_mappings` — idempotently, so rerunning
   never creates duplicate incidents and preserves an analyst's status.
5. `GET /api/incidents/{id}` assembles the full incident (evidence,
   score breakdown, ATT&CK mappings, any stored model analyses) for the
   dashboard and for report export.
6. `POST /api/incidents/{id}/analyze` (only if `llm_enabled`) builds a
   bounded, delimited evidence prompt, calls Ollama, validates the JSON
   response and that every cited event ID is real, and stores the result
   with its model tag/prompt version/latency for reproducibility.

## Known architectural limitations

See the README's "Limitations" section — this file covers structure, not
caveats about detection accuracy or scope.
