"""Evaluation against the labelled synthetic test dataset (spec section 14).

Runs the parser + correlation pipeline entirely in memory against the
bundled scenario data (spec section 13) and checks the result against
data/samples/labels.json's ground truth, independent of whatever is
currently stored in the live database. This keeps the evaluation
reproducible: re-running it always re-derives the same labelled scenarios
from the generator rather than depending on prior ingest state.
"""

import json
import time

from app.parsers import auth_logs, suricata
from app.services import correlation
from app.services.sample_generator import build_auth_log_lines, build_labels, build_suricata_alerts


def _sample_rows() -> list[dict]:
    eve_text = "\n".join(json.dumps(a) for a in build_suricata_alerts())
    auth_text = "\n".join(build_auth_log_lines())
    eve_events = suricata.parse_eve_json(eve_text).events
    auth_events = auth_logs.parse_ssh_auth_log(auth_text, assumed_year=2026).events
    return [e.to_row() for e in (eve_events + auth_events)]


def _matches(event: dict, criteria: dict) -> bool:
    return all(event.get(k) == v for k, v in criteria.items())


def run_evaluation() -> dict:
    labels = build_labels()
    rows = _sample_rows()

    started = time.monotonic()
    incidents = correlation.correlate(rows)
    deduped = correlation.deduplicate(rows)
    processing_latency_ms = int((time.monotonic() - started) * 1000)

    scenario_results = []
    tp = fn = fp = tn = 0

    for scenario in labels["scenarios"]:
        sid = scenario["id"]

        if scenario.get("expected_correlation"):
            match = scenario["match"]
            min_events = scenario.get("min_linked_events", 1)
            found = any(
                len(inc.event_rows) >= min_events and all(_matches(e, match) for e in inc.event_rows)
                for inc in incidents
            )
            if found:
                tp += 1
                scenario_results.append({"id": sid, "result": "true_positive", "description": scenario["description"]})
            else:
                fn += 1
                scenario_results.append({"id": sid, "result": "false_negative", "description": scenario["description"]})

        elif "unrelated_pair" in scenario:
            group_a, group_b = scenario["unrelated_pair"]
            linked_both = any(
                any(_matches(e, group_a) for e in inc.event_rows) and any(_matches(e, group_b) for e in inc.event_rows)
                for inc in incidents
            )
            if linked_both:
                fp += 1
                scenario_results.append({"id": sid, "result": "false_positive", "description": scenario["description"]})
            else:
                tn += 1
                scenario_results.append({"id": sid, "result": "true_negative", "description": scenario["description"]})

        elif sid == "scenario_4_duplicate_alerts":
            match, expected = scenario["match"], scenario["expected_duplicate_count"]
            rep = next((e for e in deduped if _matches(e, match)), None)
            passed = rep is not None and rep.get("duplicate_count") == expected
            scenario_results.append({
                "id": sid, "result": "pass" if passed else "fail", "description": scenario["description"],
                "detail": f"duplicate_count={rep['duplicate_count'] if rep else None}, expected={expected}",
            })

        elif sid == "scenario_3_benign_high_volume_transfer":
            match = scenario["match"]
            singleton = next(
                (inc for inc in incidents if inc.rule_fired == "unusual_outbound_transfer_singleton"
                 and all(_matches(e, match) for e in inc.event_rows)),
                None,
            )
            passed = singleton is not None and singleton.confidence == "Low"
            scenario_results.append({
                "id": sid, "result": "pass" if passed else "fail", "description": scenario["description"],
                "detail": "flagged as a low-confidence singleton" if passed else "not flagged as expected",
            })

        elif sid == "scenario_6_model_hallucination_check":
            no_incident = not any(
                any(e["event_type"] == "dns_anomaly" for e in inc.event_rows) for inc in incidents
            )
            scenario_results.append({
                "id": sid, "result": "pass" if no_incident else "fail", "description": scenario["description"],
                "detail": "correctly created no incident from minimal evidence" if no_incident else "unexpectedly created an incident",
            })

    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall = tp / (tp + fn) if (tp + fn) > 0 else None
    false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else None

    return {
        "processing_latency_ms": processing_latency_ms,
        "confusion_matrix": {"true_positive": tp, "false_negative": fn, "false_positive": fp, "true_negative": tn},
        "precision": precision,
        "recall": recall,
        "false_positive_rate": false_positive_rate,
        "scenario_results": scenario_results,
        "caveat": (
            "This runs against a small, fixed synthetic dataset (spec sections 13-14). The precision/recall/FPR "
            "figures demonstrate the evaluation methodology, not statistically significant detection performance."
        ),
    }


def llm_evaluation_summary(conn) -> dict:
    rows = conn.execute("SELECT model_tag, validation_status, latency_ms FROM model_analyses").fetchall()
    if not rows:
        return {"total_analyses": 0, "note": "No LLM analyses have been requested yet."}

    total = len(rows)
    valid = sum(1 for r in rows if r["validation_status"] == "valid")
    avg_latency = sum(r["latency_ms"] or 0 for r in rows) / total

    by_model: dict = {}
    for r in rows:
        stats = by_model.setdefault(r["model_tag"], {"total": 0, "valid": 0, "latencies": []})
        stats["total"] += 1
        if r["validation_status"] == "valid":
            stats["valid"] += 1
        stats["latencies"].append(r["latency_ms"] or 0)

    per_model = [
        {
            "model_tag": tag,
            "total_analyses": s["total"],
            "validity_rate": s["valid"] / s["total"],
            "avg_latency_ms": sum(s["latencies"]) / len(s["latencies"]),
        }
        for tag, s in by_model.items()
    ]

    return {
        "total_analyses": total,
        "overall_validity_rate": valid / total,
        "overall_avg_latency_ms": avg_latency,
        "per_model": per_model,
        "note": "Resource use (CPU/memory per model) is not instrumented in this environment; "
                "latency and JSON/schema validity are measured directly.",
    }
