"""Generates synthetic Suricata-style eve.json alerts and SSH auth logs for
BlueShield demo/testing, covering the six controlled scenarios in spec
section 13. Only documentation-only IP ranges are used (RFC 5737):
192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24. Nothing here touches a real
network; this just writes synthetic text/JSON files to disk.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_TIME = datetime(2026, 10, 26, 10, 0, 0, tzinfo=timezone.utc)


def _suricata_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000000+0000")


def _syslog_ts(dt: datetime) -> str:
    day = f"{dt.day:2d}"  # syslog pads single-digit days with a space, e.g. "Oct  5"
    return f"{dt.strftime('%b')} {day} {dt.strftime('%H:%M:%S')}"


def _alert(dt, src_ip, src_port, dest_ip, dest_port, host, signature, signature_id,
           category="Attempted Information Leak", severity=2, flow_id=None):
    return {
        "timestamp": _suricata_ts(dt),
        "flow_id": flow_id or abs(hash((src_ip, dest_ip, dt.isoformat()))) % 10**13,
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": "TCP",
        "host": host,
        "alert": {
            "signature_id": signature_id,
            "signature": signature,
            "category": category,
            "severity": severity,
        },
    }


def _ssh_line(dt, host, pid, outcome, user, src_ip, src_port):
    verb = "Accepted password" if outcome == "success" else "Failed password for invalid user"
    if outcome == "success":
        body = f"Accepted password for {user} from {src_ip} port {src_port} ssh2"
    else:
        body = f"Failed password for invalid user {user} from {src_ip} port {src_port} ssh2"
    return f"{_syslog_ts(dt)} {host} sshd[{pid}]: {body}"


def build_suricata_alerts() -> list[dict]:
    alerts = []

    # Scenario 1: port scan -> SSH failures (same src/dest/host, within 10 min window)
    alerts.append(_alert(
        BASE_TIME, "192.0.2.10", 53012, "192.0.2.20", 22, "lab-server-1",
        "ET SCAN Potential SSH Scan", 2001219,
    ))

    # Scenario 3: benign high-volume outbound transfer (uncertain, not confirmed exfiltration)
    alerts.append(_alert(
        BASE_TIME + timedelta(hours=1), "192.0.2.30", 44021, "203.0.113.9", 443, "lab-server-3",
        "ET POLICY Large Outbound Data Transfer", 2001500,
        category="Potential Data Exfiltration", severity=2,
    ))

    # Scenario 4: duplicate alerts — same signature/src/dest repeated four times in seconds
    dup_base = BASE_TIME + timedelta(hours=1, minutes=15)
    for i, offset_seconds in enumerate([0, 5, 8, 12]):
        alerts.append(_alert(
            dup_base + timedelta(seconds=offset_seconds), "198.51.100.10", 51000 + i,
            "198.51.100.20", 3389, "lab-server-5",
            "ET SCAN Potential RDP Scan", 2001777,
            flow_id=5551000,
        ))

    # Scenario 5: unrelated event A (port scan, isolated source/dest, no follow-up)
    alerts.append(_alert(
        BASE_TIME + timedelta(hours=2), "203.0.113.50", 55010, "203.0.113.60", 445, "lab-server-6",
        "ET SCAN Potential SMB Scan", 2001881,
    ))

    # Scenario 6: minimal-evidence DNS anomaly (no username, no login outcome, no malware ID) —
    # used to check that an LLM analysis does not invent facts beyond this evidence.
    alerts.append(_alert(
        BASE_TIME + timedelta(hours=5), "192.0.2.40", 33001, "203.0.113.100", 53, "lab-server-4",
        "ET DNS Unusually Long DNS Query (Possible DGA)", 2002100,
        category="Potentially Bad Traffic", severity=1,
    ))

    # Malformed entry on purpose, to exercise parser error handling.
    alerts.append({"event_type": "alert", "src_ip": "192.0.2.99"})  # missing required fields

    return alerts


def build_auth_log_lines() -> list[str]:
    lines = []

    # Scenario 1 continued: SSH failures from the same scanning source, same window
    for i, (minute, user) in enumerate([(1, "root"), (1.5, "admin"), (2, "test"), (2.5, "root")]):
        dt = BASE_TIME + timedelta(minutes=minute)
        lines.append(_ssh_line(dt, "lab-server-1", 1000 + i, "fail", user, "192.0.2.10", 53013 + i))

    # Scenario 2: failures followed by a successful login for the same account/host/source
    scenario2_base = BASE_TIME + timedelta(minutes=30)
    for i, minute_offset in enumerate([0, 0.33, 0.66]):
        dt = scenario2_base + timedelta(minutes=minute_offset)
        lines.append(_ssh_line(dt, "lab-server-2", 2000 + i, "fail", "svc_test", "198.51.100.5", 54020 + i))
    lines.append(_ssh_line(scenario2_base + timedelta(minutes=1), "lab-server-2", 2010, "success",
                            "svc_test", "198.51.100.5", 54030))

    # Scenario 5: unrelated event B — different source/dest/host, ~2.5 hours after event A
    # and outside any shared correlation window, so it must NOT be linked to scenario 5's scan.
    unrelated_dt = BASE_TIME + timedelta(hours=4, minutes=30)
    lines.append(_ssh_line(unrelated_dt, "lab-server-7", 3000, "fail", "guest", "198.51.100.77", 60000))
    lines.append(_ssh_line(unrelated_dt + timedelta(seconds=20), "lab-server-7", 3001, "fail",
                            "guest", "198.51.100.77", 60001))

    # Malformed line on purpose (truncated/garbled), to exercise parser error handling.
    lines.append("Oct 26 ??:??:?? lab-server-1 sshd[]: garbled entry no useful fields")

    return lines


def build_labels() -> dict:
    """Ground-truth labels for the correlation/evaluation tests (spec section 14)."""
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scenarios": [
            {
                "id": "scenario_1_portscan_to_ssh_failures",
                "description": "Port scan followed by repeated SSH failures, same source/dest/host within window.",
                "expected_correlation": True,
                # dest_ip is intentionally left out: the SSH auth-log events in this
                # group carry no dest_ip (only the Suricata scan event does), so
                # host_id is the correlating anchor shared by every event here.
                "match": {"src_ip": "192.0.2.10", "host_id": "lab-server-1"},
                "min_linked_events": 5,
            },
            {
                "id": "scenario_2_failures_then_success",
                "description": "SSH failures followed by a successful login for the same account/host.",
                "expected_correlation": True,
                "match": {"src_ip": "198.51.100.5", "host_id": "lab-server-2", "username": "svc_test"},
                "min_linked_events": 4,
            },
            {
                "id": "scenario_3_benign_high_volume_transfer",
                "description": "Large outbound transfer that should be flagged but kept low-confidence, not treated as confirmed exfiltration.",
                "expected_correlation": False,
                "match": {"src_ip": "192.0.2.30", "dest_ip": "203.0.113.9"},
                "min_linked_events": 1,
            },
            {
                "id": "scenario_4_duplicate_alerts",
                "description": "Four duplicate scan alerts that should deduplicate into one event record with count=4.",
                "expected_correlation": False,
                "match": {"src_ip": "198.51.100.10", "dest_ip": "198.51.100.20"},
                "expected_duplicate_count": 4,
            },
            {
                "id": "scenario_5_unrelated_events",
                "description": "A port scan and a separate, later SSH-failure pair on unrelated hosts; must not be linked together.",
                "expected_correlation": False,
                "unrelated_pair": [
                    {"src_ip": "203.0.113.50", "dest_ip": "203.0.113.60"},
                    {"src_ip": "198.51.100.77", "host_id": "lab-server-7"},
                ],
            },
            {
                "id": "scenario_6_model_hallucination_check",
                "description": "Minimal-evidence DNS anomaly with no username/login outcome/malware ID, for LLM-output validation tests.",
                "expected_correlation": False,
                "match": {"src_ip": "192.0.2.40", "dest_ip": "203.0.113.100"},
            },
        ],
    }


def generate_all(output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)

    alerts = build_suricata_alerts()
    eve_path = output_dir / "eve.json"
    with eve_path.open("w") as f:
        for alert in alerts:
            f.write(json.dumps(alert) + "\n")

    auth_path = output_dir / "auth.log"
    with auth_path.open("w") as f:
        f.write("\n".join(build_auth_log_lines()) + "\n")

    labels_path = output_dir / "labels.json"
    labels_path.write_text(json.dumps(build_labels(), indent=2))

    return {"eve_json": str(eve_path), "auth_log": str(auth_path), "labels": str(labels_path)}


if __name__ == "__main__":
    import sys

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent.parent / "data" / "samples"
    result = generate_all(target)
    print(json.dumps(result, indent=2))
