# BlueShield — Network Threat Detection and Attack Correlation Platform

> **Project brief for a third-year B.Tech Cybersecurity Network Security project**  
> **Working title:** BlueShield: AI-Assisted Network Threat Detection and Attack Correlation Platform Using Local LLMs  
> **Core idea:** Turn individual security alerts into a coherent incident story, with evidence, severity, an attack timeline, and practical defensive recommendations.  
> **Status:** Proposed design and implementation plan. Model names, installed versions, hardware, and final evaluation results must be verified during implementation.

---

## 1. Executive Summary

Security tools can generate many individual alerts. A port scan, repeated SSH login failures, a successful login, and an unusual outbound transfer may each appear as separate events. An analyst must decide whether these events are unrelated or could represent stages of one intrusion.

BlueShield is a defensive security platform that ingests network-security alerts and selected system logs, normalizes them into a common format, correlates related events, assigns a transparent risk score, and presents incidents through a dashboard. It can use local language models served by Ollama to help explain an incident, draft an evidence-based summary, map events to likely MITRE ATT&CK techniques, and suggest investigation or containment steps.

**Important design principle:** deterministic security tools and Python logic perform detection and correlation. The local language models assist with interpretation and reporting; they do not independently decide that an attack definitely occurred. Every generated conclusion should be traceable to the underlying events.

The initial version should work on sample logs and controlled lab traffic. Live network monitoring, more integrations, and automated response are optional extensions.

## 2. Problem Statement

Security alerts often arrive from separate tools and are difficult to interpret together. Analysts may need to manually compare timestamps, source and destination addresses, usernames, affected hosts, and alert types. This can delay triage and make it harder to identify multi-stage activity.

The project addresses this problem by creating a local, explainable workflow that:
1. Collects events from selected sources.
2. Normalizes events into a consistent schema.
3. Detects known suspicious patterns using rules and security-tool alerts.
4. Correlates events that share meaningful attributes and occur within a configurable time window.
5. Assigns a transparent risk score and confidence level.
6. Displays the incident timeline and supporting evidence.
7. Uses local LLMs to produce a draft analyst explanation and defensive recommendations.
8. Stores incidents and exports a report for review.

## 3. Objectives

### Primary objectives
- Ingest and parse sample or lab-generated Suricata, Zeek, firewall, and authentication logs.
- Normalize events to a common JSON structure.
- Detect selected behaviors such as port-scan alerts, repeated authentication failures, suspicious successful logins, and unusual outbound traffic.
- Correlate events by host, source, destination, account, time, and related event sequence.
- Generate a risk score with understandable scoring factors.
- Show incident details, evidence, and a chronological timeline on a dashboard.
- Integrate locally hosted LLMs through Ollama for incident summarization and investigation guidance.
- Produce a report containing evidence, uncertainty, and recommended next steps.

### Stretch objectives
- PCAP upload and offline analysis.
- MITRE ATT&CK technique references.
- Email or desktop notifications.
- Threat-intelligence enrichment using an optional external API.
- Comparison of two local LLMs on the same incident cases.
- Evaluation of correlation precision, recall, false positives, latency, and model-output quality.

## 4. Scope and Boundaries

### In scope
- Defensive monitoring and incident triage.
- Controlled virtual lab or pre-recorded datasets.
- Safe, authorized test scenarios.
- Rule-based detection and event correlation.
- Local model inference for summaries and recommendations.
- Human-reviewed response suggestions.

### Out of scope for the initial version
- Monitoring networks without authorization.
- Exploiting real systems.
- Autonomous blocking or remediation.
- Claiming that an alert proves a compromise.
- Treating an LLM-generated explanation as authoritative evidence.
- Requiring cloud AI APIs for the core workflow.

Keep the first version small enough to finish: sample log ingestion, normalization, a handful of correlation rules, a dashboard, and local LLM summaries are a strong minimum viable product.

## 5. Proposed System Architecture

```text
Authorized lab traffic / sample logs / PCAP
                  |
        +---------+----------+
        |                    |
  Suricata alerts        Zeek logs
        |                    |
        +---------+----------+
                  |
       Optional system/auth logs
                  |
          Ingestion adapters
                  |
       Parser + normalization
                  |
        SQLite event database
                  |
       Detection and correlation
       (Python rules + time windows)
                  |
       +----------+-----------+
       |          |           |
   Risk score  Timeline   ATT&CK references
       |          |           |
       +----------+-----------+
                  |
          Incident evidence pack
                  |
          Ollama local API
          /              \
 Qwen coder model     DeepSeek model
 (structured output,  (second opinion,
  formatting, report)  analysis, summary)
          \              /
           Model output validation
                  |
          Analyst review dashboard
                  |
       Exportable incident report
```

The two models should be treated as alternative or complementary assistants, not as independent security sensors. For the first working prototype, use one model end-to-end, then add the second after the pipeline is stable.

## 6. Suggested Technology Stack

| Layer | Recommended tool | Purpose |
|---|---|---|
| Operating environment | Linux VM or host OS | Controlled security lab |
| Network sensor | Suricata | Signature-based network alerts |
| Network telemetry | Zeek (optional at first) | Connection, DNS, and protocol logs |
| Packet inspection | Wireshark / tcpdump (optional) | Validate lab traffic and inspect PCAPs |
| Backend | Python 3 | Ingestion, normalization, correlation |
| API / web application | FastAPI or Flask | Backend endpoints and dashboard |
| Database | SQLite initially | Store events, incidents, and model results |
| Dashboard | HTML/CSS/JavaScript, Bootstrap, and Chart.js | Tables, charts, incident timeline |
| Local model runtime | Ollama | Run supported models locally |
| LLM integration | Ollama local HTTP API | Submit evidence and receive model output |
| Report export | Markdown or HTML first; PDF optional | Incident reports |
| Version control | Git | Track code and team contributions |
| Test data | Synthetic logs and authorized lab data | Repeatable evaluation |

**Keep the stack manageable:** use Suricata plus sample authentication logs first. Add Zeek only when the basic version works. Avoid deploying every tool at once.

## 7. Local LLM Plan: Ollama, Qwen, and DeepSeek

The proposed local models are:
- **Qwen2.5-Coder:** use the exact available Ollama model tag and parameter size confirmed on the team’s computer. The phrase “1B parameters” must be verified; do not assume that a 1B, 1.5B, or another variant is installed.
- **DeepSeek:** identify the exact model name and size before implementation. “DeepSeek” refers to a family of models, not one specific model, and hardware requirements vary substantially.

### Recommended responsibilities

**Qwen2.5-Coder**
- Convert a compact set of normalized events into a structured draft.
- Format incident reports and concise investigation checklists.
- Help with developer-facing tasks during implementation.
- Return JSON when the selected model and prompt reliably support the required schema.

**DeepSeek**
- Produce an independent explanation of a correlated event sequence.
- Identify alternative benign explanations and missing evidence.
- Draft a second incident summary for comparison.
- Suggest defensive investigation steps.

These responsibilities are a proposed division of labor, not a claim that either model is inherently better at a given task. Compare their output on the same test cases.

### Ollama setup

Install Ollama from its official documentation for the target operating system. Then inspect the installed model tags:

```bash
ollama list
```

Pull only the exact model variants the hardware can run. Model tags can change; confirm the current tags in the Ollama model library rather than copying an unverified name.

Example invocation after selecting a verified tag:

```bash
ollama run <verified-model-tag>
```

The local API is commonly exposed at `http://localhost:11434` when Ollama is running with its default configuration. Confirm this on the actual system. Keep the API bound to localhost unless there is a deliberate, secured reason to expose it.

### Suggested inference workflow

1. Correlation engine creates an evidence pack.
2. Application removes unnecessary personal or sensitive data.
3. Application sends only relevant normalized events and explicit instructions to the selected local model.
4. Model returns a structured draft.
5. Backend validates JSON/schema, limits output length, and checks that cited event IDs exist.
6. Dashboard labels the output as **AI-generated, requires analyst review**.
7. Store model name/tag, prompt version, timestamp, output, and validation status for reproducibility.

Do not send entire raw PCAPs to a small LLM. Extract useful, bounded metadata and alerts first.

### Example prompt template

```text
Role: Defensive SOC analyst assistant.

Analyze only the evidence supplied below.
Do not invent events, IP addresses, users, timestamps, CVEs, or ATT&CK mappings.
Separate observed facts from hypotheses.
If the evidence is insufficient, say so.
Give plausible benign explanations and identify missing evidence.
Recommend safe, defensive investigation steps.
Do not perform actions or claim that remediation has occurred.

Return:
1. Summary
2. Observed evidence (include event IDs)
3. Possible attack sequence and confidence
4. Alternative benign explanations
5. Potential impact
6. Recommended investigation steps
7. Suggested containment options requiring human approval
8. Missing evidence and limitations

Evidence:
[INSERT NORMALIZED INCIDENT JSON]
```

The LLM must not be allowed to execute shell commands, change firewall rules, or isolate hosts. It only returns text/structured suggestions to the application.

## 8. Data Sources and Normalized Event Schema

Start with:
- Suricata `eve.json` alerts.
- Selected Zeek logs, such as `conn.log` and `dns.log`.
- Synthetic or lab-generated SSH/authentication logs.
- Optional firewall logs.
- Optional offline PCAP-derived events.

Normalize each source into a shared structure. Example:

```json
{
  "event_id": "evt-0001",
  "timestamp": "2026-10-26T10:15:00Z",
  "source_type": "suricata",
  "event_type": "possible_port_scan",
  "src_ip": "192.0.2.10",
  "src_port": 53000,
  "dest_ip": "192.0.2.20",
  "dest_port": 22,
  "protocol": "TCP",
  "severity": 2,
  "signature": "Example lab alert",
  "host_id": "lab-server-1",
  "username": null,
  "evidence": "Synthetic example for testing"
}
```

The addresses above are documentation-only example addresses, not indicators of a real attack. Real schemas should preserve source-specific fields where useful, including original timestamp, sensor, rule/signature ID, flow ID, and raw event reference.

### Suggested database tables
- `events`: normalized event records.
- `incidents`: incident ID, title, status, severity, confidence, created time.
- `incident_events`: many-to-many link between incidents and supporting events.
- `model_analyses`: model tag, prompt version, response, validation status, created time.
- `audit_log`: analyst changes and report exports.

Use UTC internally for timestamps and convert to local time only for display.

## 9. Detection and Correlation Engine

The correlation engine is the core of the project. It should be deterministic and testable independently of the LLM.

### Phase A: individual event detection
Consume alerts from Suricata and event types from parsed logs. For the first version, rely on established sensor alerts and a few clearly documented custom rules. Do not claim that a simple threshold catches every attack.

### Phase B: correlation keys
Use a combination of:
- Source and destination IP.
- Destination host or asset ID.
- Username/account where available.
- Event type.
- Timestamp and configurable time window.
- Sensor flow ID or connection identifiers when available.

Avoid correlating only on IP address: NAT, shared hosts, DHCP, and unrelated users can cause misleading links.

### Phase C: example correlation scenarios

| Scenario | Example event sequence | Correlation idea | Defensive follow-up |
|---|---|---|---|
| Reconnaissance followed by authentication attempts | Port-scan alert → repeated SSH failures | Same source targets same host within a short window | Review source, target exposure, and authentication logs |
| Suspicious login | Many failures → successful login for same account/host | Same account/host and bounded time window | Verify with account owner and inspect session activity |
| Possible lateral movement | Authentication from one internal host → unusual access to another host | Shared account or source host plus related access events | Review endpoint and authentication evidence |
| Possible data exfiltration | Suspicious connection → unusual outbound byte volume | Same host/flow and time window, with baseline or threshold | Validate destination, business context, and transfer contents |
| DNS anomaly | Unusually long/high-entropy DNS names or high query rate | Group by host and DNS behavior over time | Check resolver logs and destination reputation |
| Vulnerability exploitation signal | IDS signature → follow-on connection or process/auth event | Same target and related time window | Verify the affected service, patch status, and host telemetry |

These sequences are **hypotheses for investigation**, not proof that a compromise took place. For example, a large outbound transfer can be a legitimate backup.

### Phase D: incident creation
Create an incident when a documented rule or combination of events crosses a defined threshold. Attach all evidence event IDs and record which rule fired. Keep a record of why each event was linked.

### Phase E: deduplication
Group repeated copies of the same alert to prevent an incident from appearing as dozens of duplicate events. Preserve the underlying event count and time range.

## 10. Risk Scoring and Confidence

Use a transparent scoring system instead of asking the LLM to invent a severity score.

An initial prototype could calculate:

```text
risk_score =
    sum(event_severity_points)
    + sequence_bonus
    + asset_criticality_bonus
    - duplicate_penalty
```

Clamp the score to a documented range, such as 0–100. Choose and tune weights using test cases; do not present example weights as industry standards.

Possible labels:
- 0–24: Informational
- 25–49: Low
- 50–74: High
- 75–100: Critical

These are project-defined categories, not official universal thresholds.

Keep **severity** separate from **confidence**:
- Severity estimates potential impact if the activity is malicious.
- Confidence estimates how strongly the observed evidence supports the incident hypothesis.

An incident may have high potential severity but low confidence. Show both on the dashboard.

## 11. MITRE ATT&CK Mapping

Where a sensor rule or verified event pattern supports it, attach relevant MITRE ATT&CK technique references. Store:
- Technique ID and name.
- Mapping rationale.
- Supporting event IDs.
- Mapping source or rule.
- Confidence/qualification.

Do not map every alert to a technique merely because it sounds similar. Reconnaissance activity observed in a lab may not establish that an internal host was compromised. Verify technique names and IDs against the official MITRE ATT&CK knowledge base before the final report.

## 12. Dashboard Requirements

### Overview page
- Total events processed.
- Open incidents.
- Incidents by severity.
- Event volume over time.
- Top source/destination hosts.
- Most common alert categories.
- Data ingestion status and last update.

### Incident list
- Incident ID and title.
- First and last observed time.
- Severity and confidence.
- Source/target hosts where known.
- Number of supporting events.
- Status: New, Investigating, Contained, Closed.

### Incident detail page
- Human-readable incident summary.
- Chronological event timeline.
- Evidence table with event IDs and source.
- Correlation rules that fired.
- ATT&CK references with rationale.
- AI-generated analysis and model tag.
- Alternative explanations and missing evidence.
- Recommended next steps.
- Analyst notes and status history.

### Reports
Generate Markdown or HTML first. Add PDF export after the incident schema and report content are stable. Include evidence, scoring rationale, model name/version, limitations, and analyst-review status.

## 13. Controlled Attack Scenarios for Testing

Perform testing only in an isolated virtual lab or with explicit authorization. Use synthetic logs if a real attack simulation is unnecessary.

### Scenario 1: Port scan followed by SSH login failures
**Generate:** a harmless, controlled scan in the lab or replay synthetic sensor events.  
**Expected:** scan alert and authentication failures are linked when source, target, and time conditions match.  
**Verify:** incident timeline contains both event types and explains the correlation rule.

### Scenario 2: Authentication failures followed by a successful lab login
**Generate:** failed and successful authentication events using a test account in a lab.  
**Expected:** one suspicious-authentication incident with event IDs and a bounded time window.  
**Verify:** the system does not claim a compromise solely because a login succeeded.

### Scenario 3: Benign high-volume outbound transfer
**Generate:** a known benign file transfer between lab machines.  
**Expected:** a threshold-based rule may flag it, but the incident includes uncertainty and an analyst validation step.  
**Verify:** the dashboard distinguishes unusual volume from confirmed exfiltration.

### Scenario 4: Duplicate alerts
**Generate:** repeated copies of the same test alert.  
**Expected:** deduplication limits alert noise while retaining event counts and raw evidence.

### Scenario 5: Unrelated events
**Generate:** a port scan from one source and unrelated login failures from another host outside the correlation window.  
**Expected:** the engine should not combine them into one attack chain without a defensible link.

### Scenario 6: Model hallucination check
**Supply:** evidence with no username, no confirmed successful login, and no malware indicator.  
**Expected:** the model should state that those facts are unknown, not invent them.

## 14. Evaluation Plan

Create a fixed test dataset with labelled scenarios: related event sequences, unrelated events, duplicates, and benign high-volume traffic.

Measure:
- **Correlation precision:** of the event groups linked by the system, how many are correctly linked?
- **Correlation recall:** of the known related event groups in the test set, how many are linked?
- **False-positive rate:** how often benign test activity is incorrectly escalated.
- **Detection coverage:** which explicitly scoped scenarios the configured rules identify.
- **Processing latency:** time from event ingestion to incident creation.
- **LLM latency:** time for a model response.
- **Evidence faithfulness:** whether model claims are supported by cited event IDs.
- **JSON/schema validity:** percentage of outputs that pass validation.
- **Resource use:** approximate memory and CPU use for each local model.

Compare Qwen and DeepSeek using the same cases, prompt, and evidence. Have a human review outputs against a rubric. Do not claim improved detection accuracy merely because the LLM writes a convincing summary. Detection performance should be measured independently from report quality.

## 15. Implementation Roadmap

### Milestone 1 — Requirements and environment
- Confirm operating system, CPU/RAM, available disk, and GPU if any.
- Install Python, Git, and Ollama.
- Choose the first data source and verify a sample log.
- Create a repository and task board.

**Deliverable:** environment checklist and sample data.

### Milestone 2 — Parsing and normalization
- Build a parser for one source, preferably Suricata JSON or a small documented synthetic JSON format.
- Validate timestamps, IP addresses, ports, and required fields.
- Store normalized events in SQLite.
- Add parser tests for malformed or missing fields.

**Deliverable:** searchable normalized events.

### Milestone 3 — Correlation rules
- Implement two or three rules first.
- Add time windows, correlation keys, evidence references, and deduplication.
- Write unit tests for related and unrelated event sequences.

**Deliverable:** reproducible incidents from test logs.

### Milestone 4 — Risk and incident records
- Add scoring with documented factors.
- Keep severity and confidence separate.
- Save incident-event relationships and rule explanations.

**Deliverable:** transparent incident records.

### Milestone 5 — Dashboard
- Build overview, incident list, incident details, and timeline.
- Add filters and status updates.
- Use a small test dataset to make the demo repeatable.

**Deliverable:** working end-to-end dashboard without LLMs.

### Milestone 6 — Ollama integration
- Verify exact Qwen and DeepSeek tags supported by the local machine.
- Call the local Ollama API from the backend.
- Validate model output and show evidence-linked summaries.
- Compare the models on a shared test set.

**Deliverable:** local AI incident assistant with a human-review label.

### Milestone 7 — Testing and polish
- Run the controlled scenarios.
- Record metrics and limitations.
- Improve error handling, duplicate detection, and documentation.
- Prepare screenshots, demo steps, and viva answers.

**Deliverable:** final tested prototype and evaluation report.

A realistic minimum viable project is milestones 1–5. Treat model integration and additional sensors as later milestones, not prerequisites for the core project to work.

## 16. Suggested Repository Structure

```text
blueshield/
├── README.md
├── requirements.txt
├── .env.example
├── app/
│   ├── main.py
│   ├── routes/
│   ├── schemas/
│   ├── services/
│   │   ├── ingestion.py
│   │   ├── normalization.py
│   │   ├── correlation.py
│   │   ├── risk_scoring.py
│   │   ├── mitre_mapping.py
│   │   ├── ollama_client.py
│   │   └── report_builder.py
│   ├── parsers/
│   │   ├── suricata.py
│   │   ├── zeek.py
│   │   └── auth_logs.py
│   ├── database/
│   ├── templates/
│   └── static/
├── data/
│   ├── samples/
│   └── generated/
├── tests/
│   ├── test_parsers.py
│   ├── test_correlation.py
│   ├── test_risk_scoring.py
│   └── test_llm_validation.py
├── docs/
│   ├── architecture.md
│   ├── test_plan.md
│   └── evaluation.md
└── reports/
```

Do not commit real logs, credentials, API keys, personal data, or sensitive packet captures to a public repository.

## 17. Example API Endpoints

Possible FastAPI endpoints:
- `GET /api/health` — service status.
- `GET /api/events` — filter and paginate normalized events.
- `GET /api/incidents` — list incidents.
- `GET /api/incidents/{incident_id}` — incident evidence and timeline.
- `POST /api/ingest/sample` — ingest an authorized sample file.
- `POST /api/incidents/{incident_id}/analyze` — request an LLM draft.
- `POST /api/incidents/{incident_id}/status` — update status with an audit entry.
- `GET /api/incidents/{incident_id}/report` — generate or retrieve a report.

Validate file types, file sizes, schema, and access permissions. Avoid exposing arbitrary file paths or command-execution endpoints.

## 18. Safety, Privacy, and Reliability

- Run attack scenarios only on systems you own or are explicitly authorized to test.
- Keep the lab isolated from production networks.
- Start with simulated events and passive logs; use active scanning only with permission.
- Treat log content as untrusted input. An attacker can put prompt-injection text into a hostname, URL, username, or log message.
- Clearly delimit log data in prompts and instruct the model to treat it as evidence, not instructions.
- Do not let model output directly run shell commands or change security controls.
- Require analyst approval for containment.
- Redact passwords, tokens, session identifiers, and unnecessary personal data.
- Keep the local model API private and do not assume that “local” automatically makes every part of the system secure.
- Log analyst actions and preserve original event references.
- Explain false positives, missing telemetry, encrypted traffic limitations, and model limitations in the report.

## 19. Expected Deliverables

1. Working Python backend and correlation engine.
2. Event parsers and normalized schema.
3. SQLite database and sample data.
4. Dashboard with incident timeline and evidence.
5. Ollama integration with verified local model tags.
6. Human-reviewed AI-generated incident summaries.
7. Test dataset and repeatable scenario results.
8. Evaluation metrics and limitations.
9. Architecture diagram and project report.
10. Demo script and presentation slides.

## 20. Demo Script for Project Evaluation

1. Open the dashboard and show that the system is running locally.
2. Import a prepared set of sample events.
3. Show the normalized events and source details.
4. Trigger a correlation rule using a known test sequence.
5. Open the incident and explain why the events were linked.
6. Show the score, severity, confidence, and timeline.
7. Request a local-model analysis and show the selected model tag.
8. Check the generated claims against event IDs.
9. Show a benign or unrelated scenario that should not be over-correlated.
10. Export a report and explain the evaluation metrics.

A reproducible, controlled demo is preferable to depending entirely on live internet traffic or unpredictable real attacks.

## 21. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Local model too slow or too large | Start with one small, verified model; keep evidence compact; make AI analysis optional |
| Model invents details | Require event IDs, validate claims where possible, and keep analyst review mandatory |
| Too many false correlations | Use time windows, multiple correlation keys, negative tests, and transparent rules |
| Sensor setup takes too long | Begin with sample logs and add live telemetry later |
| Dashboard scope grows too large | Build the incident list, details, and timeline first |
| No reliable ground truth | Create labelled synthetic scenarios and document how labels were assigned |
| Dependency/API changes | Pin versions and record model tags and configuration |
| Project depends on a single model | Keep LLM integration behind a small interface and support a no-LLM mode |

## 22. What Makes This Project Distinct

The novelty should not be described as “using AI to detect attacks” alone. A more defensible contribution is:

- **Evidence-linked correlation:** every incident includes the events and rules that caused it to be created.
- **Noise reduction:** duplicate alerts are grouped while original event counts remain available.
- **Explainable scoring:** severity is calculated from documented factors rather than an opaque model response.
- **Local-first AI assistance:** event explanations and report drafts can be produced without sending logs to a cloud LLM.
- **Model comparison:** Qwen and DeepSeek are evaluated on the same evidence for factual grounding, output validity, usefulness, and latency.
- **False-correlation testing:** the system explicitly tests unrelated events and benign activity, not just successful attack examples.

These are implementation goals to validate, not results to claim before testing.

## 23. Questions the Team Must Decide

Before coding, agree on:
1. What operating system and hardware will run the project?
2. Which exact Qwen and DeepSeek model tags can run within available memory?
3. Will the initial input be sample JSON logs, Suricata alerts, or both?
4. Is the first version offline/sample-based or connected to a controlled virtual lab?
5. Which two or three scenarios will be implemented first?
6. Who owns ingestion, correlation, dashboard, LLM integration, testing, and documentation?
7. What is the deadline and what does the course rubric require?

## 24. Suggested Work Split for a Team

For a team of four:
- **Member 1 — Ingestion and parsers:** sample data, Suricata/Zeek parsing, normalization.
- **Member 2 — Detection and correlation:** correlation rules, risk scoring, tests.
- **Member 3 — Backend and dashboard:** API, database, incident pages, timeline.
- **Member 4 — Local LLM and evaluation:** Ollama integration, output validation, model comparison, report quality.

All members should understand the complete architecture for the viva. Merge code through Git and agree on the event schema before parallel development.

## 25. Final Recommendation

Build a reliable rule-based event-correlation system first, then add local LLM assistance. The project should still detect, correlate, and display incidents when Ollama is unavailable. This separation makes the design more reliable, easier to evaluate, and easier to explain academically.

**One-sentence pitch:**  
*BlueShield is a local-first blue-team platform that converts network and authentication alerts into explainable, evidence-backed incidents using deterministic correlation, transparent risk scoring, and locally hosted Qwen/DeepSeek models for analyst assistance.*

---

## References to Consult

Use official documentation and verify versions at implementation time:
- Ollama documentation and model library: https://ollama.com/
- Suricata documentation: https://docs.suricata.io/
- Zeek documentation: https://docs.zeek.org/
- MITRE ATT&CK: https://attack.mitre.org/
- FastAPI documentation: https://fastapi.tiangolo.com/
- SQLite documentation: https://www.sqlite.org/docs.html/
- Wireshark documentation: https://www.wireshark.org/docs/
