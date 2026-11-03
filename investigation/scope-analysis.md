# Incident Scope Analysis

## Objective

Determine whether the simulated compromise is limited to one identity or represents broader compromise within the environment.

---

## Investigation Questions

### Identity Scope

- Were any other sprayed accounts successfully authenticated?
- Were authentication methods or MFA settings modified?
- Were additional sessions created?
- Were credentials reused across other systems?
- Were privileged identities targeted?

### Email Scope

- Were additional mailbox forwarding rules created?
- Were additional inbox rules modified?
- Were other users sent suspicious messages?
- Were external recipients contacted?
- Were attachments or malicious URLs distributed?

### Network Scope

- Did the suspicious source IP communicate with other accounts or systems?
- Were additional suspicious source IPs observed?
- Was the account used to access other internal services?

### Financial Risk

- Were payment instructions modified?
- Were wire or ACH transactions initiated?
- Did recipients act on the fraudulent message?
- Was sensitive financial information exposed?

### Data Exposure

- What mailbox data was available to the compromised user?
- Did forwarding transmit sensitive information externally?
- Were attachments accessed or transmitted?
- Was member or customer information potentially exposed?

---

## Current Findings

The synthetic dataset confirms compromise of:

`j.smith@summitcu.example`

No successful authentication is currently observed for the other password-spray targets.

The affected identity performed:

- External mailbox forwarding
- Suspicious inbox-rule creation
- Payment-related email activity

---

## Current Scope Assessment

The available evidence supports one confirmed compromised identity.

However, the incident should not be considered fully scoped until additional telemetry confirms whether:

- Other identities were compromised
- Additional malicious mailbox activity occurred
- Financial transactions were affected
- Sensitive information was accessed or transmitted

---

## Additional Telemetry Requested

A real investigation would request:

- Identity-provider authentication logs
- MFA and conditional-access logs
- Endpoint/EDR telemetry
- Mailbox audit logs
- Email gateway telemetry
- DNS logs
- Proxy or firewall logs
- Financial transaction logs
- Privileged-access logs
- Threat-intelligence enrichment

---

## Analyst Conclusion

The current evidence supports a high-confidence account takeover affecting one user.

> Further investigation would be required before declaring the incident fully contained or concluding that no additional identities, financial processes, or sensitive data were affected.