"""MITRE ATT&CK technique mapping (spec section 11).

Only maps a technique where a specific supporting event in the incident's
evidence justifies it — never "every alert gets a technique because it
sounds similar." Technique IDs/names below were verified against
https://attack.mitre.org/ at the time this was written; re-verify before
using in a final report, since MITRE updates its knowledge base.
"""

MITRE_RULES = {
    "recon_to_auth_failure": [
        {
            "technique_id": "T1595",
            "technique_name": "Active Scanning",
            "tactic": "Reconnaissance",
            "qualification": "possible",
            "rationale": (
                "A port-scan alert against the target host is consistent with active "
                "scanning reconnaissance ahead of an intrusion attempt."
            ),
            "event_filter": lambda e: e["event_type"] == "possible_port_scan",
        },
        {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "qualification": "possible",
            "rationale": (
                "Repeated SSH authentication failures from the same source immediately "
                "following the scan are consistent with password-guessing attempts."
            ),
            "event_filter": lambda e: e["event_type"] == "ssh_login_failure",
        },
    ],
    "brute_force_then_success": [
        {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "qualification": "possible",
            "rationale": (
                "Multiple failed logins for the same account preceded a successful login, "
                "consistent with brute-force credential access."
            ),
            "event_filter": lambda e: e["event_type"] == "ssh_login_failure",
        },
        {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "tactic": "Initial Access, Persistence, Privilege Escalation, Defense Evasion",
            "qualification": "possible, unconfirmed",
            "rationale": (
                "A successful login followed a burst of failures; this may indicate use of a "
                "compromised valid account, or may simply be the legitimate owner succeeding "
                "after mistyping a password. Analyst verification is required before concluding "
                "either way."
            ),
            "event_filter": lambda e: e["event_type"] == "ssh_login_success",
        },
    ],
    "unusual_outbound_transfer_singleton": [
        {
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration",
            "qualification": "low-confidence, unconfirmed — a scheduled backup or other benign transfer is an equally plausible explanation",
            "rationale": (
                "A single high-volume outbound-transfer alert, with no corroborating event, "
                "weakly matches an exfiltration pattern. This is the weakest mapping category: "
                "do not report it as confirmed exfiltration."
            ),
            "event_filter": lambda e: e["event_type"] == "unusual_outbound_transfer",
        },
    ],
}


def map_incident(candidate) -> list[dict]:
    """Returns MITRE ATT&CK mappings for a correlation.CandidateIncident,
    one entry per technique that has at least one supporting event.
    """
    mappings = []
    for technique in MITRE_RULES.get(candidate.rule_fired, []):
        supporting_event_ids = [e["event_id"] for e in candidate.event_rows if technique["event_filter"](e)]
        if not supporting_event_ids:
            continue
        mappings.append({
            "technique_id": technique["technique_id"],
            "technique_name": technique["technique_name"],
            "tactic": technique["tactic"],
            "rationale": technique["rationale"],
            "supporting_event_ids": supporting_event_ids,
            "mapping_source": f"rule:{candidate.rule_fired}",
            "qualification": technique["qualification"],
        })
    return mappings
