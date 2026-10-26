# BlueShield — Network Threat Detection and Attack Correlation Platform

Local-first blue-team platform that turns normalized security alerts into
evidence-linked incidents with transparent risk scoring, MITRE ATT&CK
mapping, and optional local LLM (Ollama) analyst assistance. See
[`docs/architecture.md`](docs/architecture.md) for design notes and the
project brief at `../BlueShield_Network_Threat_Detection_Project.md`.

**Status:** core platform complete and tested (parsers, correlation
engine, risk scoring, MITRE mapping, REST API, dashboard, Ollama
integration, evaluation harness). Zeek/PCAP ingestion, PDF export, and live
network capture are out of scope for this version (spec section 4).

## Setup

```bash
cd blueshield
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Run

```bash
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/ — the dashboard loads empty until you ingest
data (see the demo script below).

The app runs **fully without Ollama** (`LLM_ENABLED=false` in `.env` and in
the Settings page by default). Every page, the correlation engine, risk
scoring, and MITRE mapping work with no LLM installed.

## Run tests

```bash
pytest
```

51 tests cover parsers (valid + malformed input), correlation (related
*and* unrelated event sequences, IP-alone rejection, time-window
boundaries), risk scoring (label boundaries, clamping, duplicate penalty),
MITRE mapping (evidence-gated), LLM output validation (schema, hallucinated
event IDs, graceful network failure), the evaluation harness, and the full
REST API against an isolated test database.

## Ollama setup (optional, for AI-assisted analysis)

1. Install Ollama: https://ollama.com/
2. Pull the model tags your hardware can run, then verify:
   ```bash
   ollama list
   ```
3. In the dashboard's **Settings** page (or `.env`), set `LLM_ENABLED=true`
   and the exact primary/secondary model tags. Changes apply immediately,
   no restart needed.
4. The dashboard's incident-detail page can then request an analysis from
   either model, or **Compare both models** side by side on the same
   incident.

If Ollama isn't running or the model tag isn't pulled, the analyze
endpoint returns a clean `error` result (stored with the failure reason) —
it never crashes the app.

## 10-step demo script

1. Open http://127.0.0.1:8000/ — note the dashboard is running locally,
   with an empty-state message since no data is loaded yet.
2. Go to **Ingest** → click **Load demo data** (loads the bundled synthetic
   Suricata `eve.json` + SSH `auth.log`, spec section 13 scenarios).
3. Go to **Events** → show the normalized events, filter by `event_type`
   or `src_ip`, click a row to see the full raw normalized event.
4. Back on **Ingest**, click **Run correlation after load** (or use the
   **Incidents** page's "Run correlation now" button) to trigger the
   correlation engine on a known test sequence (port scan → SSH failures).
5. Open that incident from the **Incidents** list — explain the "why these
   events were linked" rationale and which rule fired.
6. Point out the **severity score** (0-100, with a visible factor
   breakdown), **severity label**, and **confidence** — shown as two
   separate values, not one conflated number.
7. In the **AI analysis** panel, request an analysis (or show the
   "disabled" message if Ollama isn't set up) — note the model tag shown
   and the **"AI-generated, requires analyst review"** label.
8. Open the incident's **evidence table** and cross-check that every event
   ID the AI analysis cites actually exists in that table (the backend
   already rejects any response citing an unknown event ID).
9. Show **scenario 5** (the two unrelated event groups) on the **Events**
   page or Incidents list — confirm no incident links them together,
   demonstrating the engine doesn't over-correlate.
10. Go to **Reports**, export the first incident as Markdown or HTML, then
    go to **Evaluation** and walk through precision/recall/false-positive
    rate computed against the labelled synthetic dataset.

## Limitations

- **Small, fixed evaluation dataset.** The precision/recall/FPR numbers on
  the Evaluation page come from 6 synthetic scenarios (spec section 13),
  not a statistically significant sample — they demonstrate the
  methodology, not real-world detection accuracy.
- **Three correlation rules only.** Recon→auth-failure, brute-force→
  success, and a lone-high-volume-transfer flag. Lateral movement and DNS
  anomaly correlation (spec section 9, Phase C table) are designed for but
  not implemented as rules yet.
- **No Zeek, PCAP, or live capture.** Suricata `eve.json` and SSH auth logs
  only; `app/parsers/zeek.py` is a stub. Scoped out per spec section 4/15
  (milestones 1-5 are the MVP; this build also completes 6-9).
- **Syslog timestamps have no year.** The auth-log parser is given an
  assumed year by the caller (demo data assumes 2026); a real deployment
  should source this from collector metadata, not assume "current year."
- **Asset criticality is a static JSON file** (`data/asset_criticality.json`),
  not integrated with a real CMDB.
- **No resource-usage (CPU/memory) instrumentation** for LLM calls — only
  latency and JSON/schema validity are measured, since this dev
  environment can't reliably sandbox per-process resource accounting.
- **Small local models can still produce invalid JSON** or cite the wrong
  event ID; the validator catches this (`invalid_json` / `invalid_schema`
  / `unknown_event_id`) but a malformed response is simply surfaced to the
  analyst, not auto-retried or auto-corrected.
- **Single-node, single-analyst assumption.** No authentication, multi-user
  audit attribution, or role-based access control — `audit_log.actor` is
  always `"analyst"` or `"system"`.
- **Correlation runs on the whole `events` table each time**, not
  incrementally — fine at demo scale, would need windowed/streaming
  correlation for high event volume.

## Viva prep — questions to expect

**Design / architecture**
- Why is correlation deterministic Python rather than LLM-driven? (See
  "Design principle" in `docs/architecture.md` — traceability, reliability
  without network/LLM dependency, spec section 16's risk mitigation.)
- Walk through what happens, end to end, from `POST /api/ingest/sample` to
  an incident appearing on the dashboard.
- Why does deduplication only apply to Suricata/firewall-type events and
  never to auth-log events? (Be ready to explain the bug this fixed —
  genuinely separate login attempts were being merged.)
- Why is severity kept separate from confidence instead of one score?
- How would you extend the correlation engine with a new rule (e.g.
  lateral movement)? What would the "why_linked" rationale need to say?

**Correlation / scoring specifics**
- Why does the engine refuse to correlate on IP address alone? Give a
  concrete scenario where IP-only correlation would be wrong (NAT, shared
  host, DHCP reassignment).
- Explain the risk_score formula and justify each weight. These are
  project-defined, not industry-standard — how would you tune them?
- What happens on a second correlation run with no new data? (Idempotency:
  incident IDs are deterministic hashes of rule + event IDs; status is
  preserved, not reset to "New".)

**LLM integration**
- How is prompt injection mitigated when log data (which an attacker
  could influence) is sent to the LLM?
- What happens if Ollama is not running, or the model tag isn't pulled?
  Walk through the actual error path.
- How do you verify an LLM claim is grounded in evidence rather than
  hallucinated? (event ID cross-check against `known_event_ids`)
- Why is the LLM never allowed to take action (e.g., block an IP)?

**Evaluation**
- What do precision, recall, and false-positive rate mean in this
  context, concretely, for scenario 5 (the unrelated-events case)?
- Why is the evaluation dataset synthetic rather than real attack traffic?
- What's missing from a rigorous evaluation of this system (bigger
  labelled dataset, real adversarial traffic, inter-rater analyst
  agreement on "ground truth")?

**Ethics / scope**
- Why does the dashboard explicitly show "alternative benign explanations"
  and never claim a confirmed compromise?
- What would need to change before this could run against a live,
  unauthorized network? (It shouldn't, and the spec explicitly scopes that
  out — be ready to say why.)
