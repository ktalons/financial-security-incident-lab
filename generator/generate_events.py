#*******************************************************************************#
# *generate_events.py - 11/26*                                                 #
# *Title: Synthetic Security Event Generator*                                  #
# *Author: Kyle Versluis*                                                      #
# *Description: Generates synthetic BEC and account takeover security events.* #
#*******************************************************************************#

# *--- Imports ---*

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

# *--- Configuration ---*

OUTPUT_FILE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "incident-events.jsonl"
)


# *--- Constants ---*

# RFC 5737 documentation ranges prevent accidental use of real-world IP addresses.
NORMAL_IP = "198.51.100.24"
ATTACKER_IP = "203.0.113.50"

# The reserved .example TLD keeps all scenario identities fictional.
DOMAIN = "summitcu.example"
COMPROMISED_USER = f"j.smith@{DOMAIN}"

BASE_TIME = datetime(
    2026,
    11,
    3,
    15,
    0,
    0,
    tzinfo=timezone.utc,
)


# *--- Helper Functions ---*

# Keep scenario timestamps deterministic so detections and screenshots are reproducible.
def timestamp(minutes: int, seconds: int = 0) -> str:
    return (
        BASE_TIME + timedelta(minutes=minutes, seconds=seconds)
    ).isoformat().replace("+00:00", "Z")


# Build synthetic authentication telemetry using ECS-style field names.
def auth_event(
    minutes: int,
    user: str,
    source_ip: str,
    outcome: str,
    reason: str,
) -> dict:
    return {
        "@timestamp": timestamp(minutes),
        "event": {
            "category": "authentication",
            "type": "start",
            "action": "user_login",
            "outcome": outcome,
            "dataset": "synthetic.identity",
        },
        "user": {
            "email": user,
            "name": user.split("@")[0],
        },
        "source": {
            "ip": source_ip,
        },
        "authentication": {
            "method": "password",
            "reason": reason,
        },
    }


# Represent mailbox configuration changes associated with BEC persistence.
def mailbox_event(
    minutes: int,
    action: str,
    user: str,
    source_ip: str,
    details: dict,
    ) -> dict:
    return {
        "@timestamp": timestamp(minutes),
        "event": {
            "category": "email",
            "type": "change",
            "action": action,
            "outcome": "success",
            "dataset": "synthetic.mail",
        },
        "user": {
            "email": user,
            "name": user.split("@")[0],
        },
        "source": {
            "ip": source_ip,
        },
        "mailbox": details,
    }


# Represent outbound email activity after the synthetic account compromise.
def email_event(
    minutes: int,
    sender: str,
    recipients: list[str],
    subject: str,
    source_ip: str,
) -> dict:
    return {
        "@timestamp": timestamp(minutes),
        "event": {
            "category": "email",
            "type": "info",
            "action": "message_sent",
            "outcome": "success",
            "dataset": "synthetic.mail",
        },
        "source": {
            "ip": source_ip,
        },
        "email": {
            "from": sender,
            "to": recipients,
            "subject": subject,
        },
    }


# *--- Core Logic ---*

def build_events() -> list[dict]:
    events: list[dict] = []

    # Establish normal activity before malicious behavior begins.
    events.append(
        auth_event(
            0,
            COMPROMISED_USER,
            NORMAL_IP,
            "success",
            "normal_employee_login",
        )
    )

    sprayed_users = [
        f"a.lee@{DOMAIN}",
        f"m.garcia@{DOMAIN}",
        f"r.patel@{DOMAIN}",
        f"s.williams@{DOMAIN}",
        COMPROMISED_USER,
    ]

    # Reuse one source across several identities to model password spraying.
    for index, user in enumerate(sprayed_users):
        events.append(
            auth_event(
                14 + index,
                user,
                ATTACKER_IP,
                "failure",
                "invalid_password",
            )
        )

    # Additional failure establishes repeated targeting of the compromised identity.
    events.append(
        auth_event(
            20,
            COMPROMISED_USER,
            ATTACKER_IP,
            "failure",
            "invalid_password",
        )
    )

    # A successful authentication from the attacker source marks account compromise.
    events.append(
        auth_event(
            21,
            COMPROMISED_USER,
            ATTACKER_IP,
            "success",
            "valid_credentials",
        )
    )

    # External forwarding demonstrates a common BEC persistence mechanism.
    events.append(
        mailbox_event(
            27,
            "mailbox_forwarding_rule_created",
            COMPROMISED_USER,
            ATTACKER_IP,
            {
                "rule_name": "Archive",
                "forward_to": "collections@external-mail.example",
                "delete_original": False,
            },
        )
    )

    # Conceal payment-related replies to reduce the chance of user discovery.
    events.append(
        mailbox_event(
            31,
            "inbox_rule_created",
            COMPROMISED_USER,
            ATTACKER_IP,
            {
                "rule_name": "Processed",
                "condition": "subject_contains: Payment",
                "action": "move_to_deleted_items",
            },
        )
    )

    # Simulate an internal payment-change message sent from the compromised account.
    events.append(
        email_event(
            42,
            COMPROMISED_USER,
            [
                f"finance@{DOMAIN}",
                f"accounts.payable@{DOMAIN}",
            ],
            "Updated Payment Instructions",
            ATTACKER_IP,
        )
    )

    # Add response telemetry so the full incident lifecycle can be investigated.
    events.extend(
        [
            {
                "@timestamp": timestamp(47),
                "event": {
                    "category": "intrusion_detection",
                    "type": "indicator",
                    "action": "correlation_alert",
                    "outcome": "success",
                    "dataset": "synthetic.soc",
                },
                "rule": {
                    "name": (
                        "Suspicious Authentication "
                        "Followed by Mailbox Rule"
                    ),
                    "severity": "high",
                },
                "user": {
                    "email": COMPROMISED_USER,
                },
            },
            {
                "@timestamp": timestamp(57),
                "event": {
                    "category": "iam",
                    "type": "change",
                    "action": "sessions_revoked",
                    "outcome": "success",
                    "dataset": "synthetic.response",
                },
                "user": {
                    "email": COMPROMISED_USER,
                },
            },
            {
                "@timestamp": timestamp(58),
                "event": {
                    "category": "iam",
                    "type": "change",
                    "action": "account_disabled",
                    "outcome": "success",
                    "dataset": "synthetic.response",
                },
                "user": {
                    "email": COMPROMISED_USER,
                },
            },
        ]
    )

    # Sorting guarantees stable output even if event construction changes later.
    return sorted(events, key=lambda event: event["@timestamp"])


def generate_dataset() -> Path:
    # Create the output directory when the repository is run from a fresh clone.
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    events = build_events()

    with OUTPUT_FILE.open("w", encoding="utf-8") as output:
        for event in events:
            output.write(json.dumps(event) + "\n")

    print(f"[+] Generated {len(events)} synthetic events")
    print(f"[+] Output: {OUTPUT_FILE}")
    print("[+] Scenario: password spray -> account takeover -> BEC activity")

    return OUTPUT_FILE


# *--- Entry Point ---*

if __name__ == "__main__":
    generate_dataset()