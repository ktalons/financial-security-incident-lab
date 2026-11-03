#*******************************************************************************#
# *detect_incident.py — 11/26*                                                 #
# *Title: Synthetic Incident Detection Engine*                                 #
# *Author: Kyle Versluis*                                                      #
# *Description: Detects and correlates suspicious activity in synthetic logs.* #
#*******************************************************************************#

# *--- Imports ---*

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path


# *--- Configuration ---*

INPUT_FILE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "incident-events.jsonl"
)


# *--- Constants ---*

PASSWORD_SPRAY_THRESHOLD = 4

AUTH_ACTION = "user_login"
FORWARDING_ACTION = "mailbox_forwarding_rule_created"
INBOX_RULE_ACTION = "inbox_rule_created"
EMAIL_SENT_ACTION = "message_sent"


# *--- Helper Functions ---*

# Parse timestamps once so event ordering and comparisons remain consistent.
def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# Load JSONL records while preserving each event as an independent document.
def load_events(path: Path) -> list[dict]:
    events = []

    with path.open("r", encoding="utf-8") as source:
        for line in source:
            if line.strip():
                events.append(json.loads(line))

    return sorted(
        events,
        key=lambda event: parse_timestamp(event["@timestamp"]),
    )


# Safely retrieve nested values without requiring every event to share a schema.
def nested_get(event: dict, *keys: str):
    value = event

    for key in keys:
        if not isinstance(value, dict):
            return None

        value = value.get(key)

        if value is None:
            return None

    return value


# *--- Detection Logic ---*

# Detect one source failing authentication across multiple identities.
def detect_password_spray(events: list[dict]) -> list[dict]:
    failures_by_source = defaultdict(list)

    for event in events:
        action = nested_get(event, "event", "action")
        outcome = nested_get(event, "event", "outcome")
        source_ip = nested_get(event, "source", "ip")
        user = nested_get(event, "user", "email")

        if (
            action == AUTH_ACTION
            and outcome == "failure"
            and source_ip
            and user
        ):
            failures_by_source[source_ip].append(event)

    findings = []

    for source_ip, failures in failures_by_source.items():
        unique_users = {
            nested_get(event, "user", "email")
            for event in failures
        }

        if len(unique_users) >= PASSWORD_SPRAY_THRESHOLD:
            findings.append(
                {
                    "type": "password_spray",
                    "severity": "medium",
                    "source_ip": source_ip,
                    "user_count": len(unique_users),
                    "users": sorted(unique_users),
                    "first_seen": failures[0]["@timestamp"],
                    "last_seen": failures[-1]["@timestamp"],
                }
            )

    return findings


# Detect successful authentication after failed attempts from the same source.
def detect_success_after_failures(events: list[dict]) -> list[dict]:
    failed_pairs = set()
    findings = []

    for event in events:
        action = nested_get(event, "event", "action")
        outcome = nested_get(event, "event", "outcome")
        source_ip = nested_get(event, "source", "ip")
        user = nested_get(event, "user", "email")

        if action != AUTH_ACTION or not source_ip or not user:
            continue

        pair = (source_ip, user)

        if outcome == "failure":
            failed_pairs.add(pair)
            continue

        if outcome == "success" and pair in failed_pairs:
            findings.append(
                {
                    "type": "successful_login_after_failures",
                    "severity": "high",
                    "source_ip": source_ip,
                    "user": user,
                    "timestamp": event["@timestamp"],
                }
            )

    return findings


# Detect external mailbox forwarding created after account compromise.
def detect_external_forwarding(events: list[dict]) -> list[dict]:
    findings = []

    for event in events:
        action = nested_get(event, "event", "action")

        if action != FORWARDING_ACTION:
            continue

        user = nested_get(event, "user", "email")
        forward_to = nested_get(event, "mailbox", "forward_to")
        source_ip = nested_get(event, "source", "ip")

        if not user or not forward_to:
            continue

        user_domain = user.split("@")[-1].lower()
        forward_domain = forward_to.split("@")[-1].lower()

        if user_domain != forward_domain:
            findings.append(
                {
                    "type": "external_mail_forwarding",
                    "severity": "high",
                    "source_ip": source_ip,
                    "user": user,
                    "forward_to": forward_to,
                    "timestamp": event["@timestamp"],
                }
            )

    return findings


# Detect inbox rules that may conceal payment-related communication.
def detect_suspicious_inbox_rule(events: list[dict]) -> list[dict]:
    findings = []

    for event in events:
        action = nested_get(event, "event", "action")

        if action != INBOX_RULE_ACTION:
            continue

        rule_action = nested_get(event, "mailbox", "action")
        condition = nested_get(event, "mailbox", "condition")

        if rule_action != "move_to_deleted_items":
            continue

        findings.append(
            {
                "type": "suspicious_inbox_rule",
                "severity": "high",
                "user": nested_get(event, "user", "email"),
                "source_ip": nested_get(event, "source", "ip"),
                "condition": condition,
                "timestamp": event["@timestamp"],
            }
        )

    return findings


# Detect outbound payment-related email from the compromised source.
def detect_suspicious_email(events: list[dict]) -> list[dict]:
    findings = []

    for event in events:
        action = nested_get(event, "event", "action")

        if action != EMAIL_SENT_ACTION:
            continue

        subject = nested_get(event, "email", "subject") or ""

        if "payment" not in subject.lower():
            continue

        findings.append(
            {
                "type": "suspicious_payment_email",
                "severity": "high",
                "sender": nested_get(event, "email", "from"),
                "recipients": nested_get(event, "email", "to"),
                "source_ip": nested_get(event, "source", "ip"),
                "subject": subject,
                "timestamp": event["@timestamp"],
            }
        )

    return findings


# *--- Correlation Logic ---*

# Correlate multiple behaviors to raise confidence beyond a single alert.
def correlate_incident(findings: dict[str, list[dict]]) -> list[dict]:
    incidents = []

    sprays = findings["password_spray"]
    compromises = findings["successful_login_after_failures"]
    forwarding = findings["external_mail_forwarding"]

    for compromise in compromises:
        source_ip = compromise["source_ip"]
        user = compromise["user"]

        spray_match = any(
            finding["source_ip"] == source_ip
            for finding in sprays
        )

        forwarding_match = any(
            finding["source_ip"] == source_ip
            and finding["user"] == user
            for finding in forwarding
        )

        if spray_match and forwarding_match:
            incidents.append(
                {
                    "type": "account_takeover_bec",
                    "severity": "critical",
                    "confidence": "high",
                    "user": user,
                    "source_ip": source_ip,
                    "reason": (
                        "Password spray followed by successful authentication and external mailbox forwarding."
                    ),
                }
            )

    return incidents


# *--- Reporting ---*

def print_findings(
    findings: dict[str, list[dict]],
    incidents: list[dict],
) -> None:
    print()
    print("=" * 72)
    print("* FINANCIAL SECURITY INCIDENT LAB * DETECTION RESULTS *")
    print("=" * 72)

    total_findings = sum(len(items) for items in findings.values())

    print(f"\n[+] Detection finding count: {total_findings}")

    for detection_type, items in findings.items():
        print(f"\n--- {detection_type.replace('_', ' ').title()} ---")

        if not items:
            print("No findings.")
            continue

        for item in items:
            print(json.dumps(item, indent=2))

    print("\n" + "=" * 72)
    print(" POSSIBLE LINKED INCIDENTS SCENARIO DETECTED")
    print("=" * 72)

    if not incidents:
        print("\n[-] No linked incidents detected.")
        return

    for incident in incidents:
        print()
        print(f"[!] Severity:   {incident['severity'].upper()}")
        print(f"[!] Confidence: {incident['confidence'].upper()}")
        print(f"[!] Type:       {incident['type']}")
        print(f"[!] User:       {incident['user']}")
        print(f"[!] Source IP:  {incident['source_ip']}")
        print(f"[!] Reason:     {incident['reason']}")


# *--- Core Logic ---*

def analyze_incident() -> None:
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            "Synthetic event dataset not found. Run generator/generate_events.py first."
        )

    events = load_events(INPUT_FILE)

    findings = {
        "password_spray": detect_password_spray(events),
        "successful_login_after_failures": (
            detect_success_after_failures(events)
        ),
        "external_mail_forwarding": detect_external_forwarding(events),
        "suspicious_inbox_rule": detect_suspicious_inbox_rule(events),
        "suspicious_payment_email": detect_suspicious_email(events),
    }

    incidents = correlate_incident(findings)

    print(f"[+] Loaded {len(events)} synthetic events")
    print_findings(findings, incidents)


# *--- Entry Point ---*

if __name__ == "__main__":
    analyze_incident()