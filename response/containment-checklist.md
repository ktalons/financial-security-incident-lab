# Incident Containment Checklist

## Incident

**Type:** Account Takeover / Business Email Compromise  
**Severity:** Critical  
**Confidence:** High  
**Affected Identity:** `j.smith@summitcu.example`

---

## Confirmed Containment Actions

- [x] Revoke active sessions for the affected identity.
- [x] Disable the affected account.

## Recommended Immediate Containment

- [ ] Reset the affected user's credentials.
- [ ] Require secure re-enrollment of authentication factors.
- [ ] Remove unauthorized mailbox forwarding rules.
- [ ] Remove malicious or unauthorized inbox rules.
- [ ] Block confirmed malicious indicators where appropriate.
- [ ] Preserve relevant authentication and mailbox evidence.

---

## Identity Review

- [ ] Review authentication history for the affected account.
- [ ] Identify any additional successful sessions from suspicious sources.
- [ ] Review MFA registration and modification activity.
- [ ] Review password-reset activity.
- [ ] Review OAuth applications and delegated permissions.
- [ ] Identify other accounts targeted by the same source.
- [ ] Determine whether privileged credentials were exposed.

---

## Email Review

- [ ] Identify all messages sent by the compromised account during the incident.
- [ ] Identify recipients of suspicious messages.
- [ ] Remove malicious messages from internal mailboxes where possible.
- [ ] Review forwarding destinations.
- [ ] Search for similar mailbox rules across other users.
- [ ] Determine whether sensitive information was externally forwarded.

---

## Endpoint Review

- [ ] Identify devices associated with the affected user.
- [ ] Review EDR telemetry for malicious processes or persistence.
- [ ] Determine whether credentials were captured through malware.
- [ ] Isolate affected endpoints if compromise is suspected.

---

## Financial Impact Review

- [ ] Determine whether payment instructions were modified.
- [ ] Determine whether wire, ACH, or other transactions were initiated.
- [ ] Verify whether recipients acted on fraudulent instructions.
- [ ] Notify appropriate fraud or financial operations personnel.
- [ ] Preserve transaction evidence where applicable.

---

## Scope Validation

- [ ] Search for the suspicious source IP across available telemetry.
- [ ] Search for successful authentication among other targeted users.
- [ ] Review related DNS, proxy, firewall, and endpoint activity.
- [ ] Determine whether additional identities are compromised.
- [ ] Determine whether sensitive or regulated data was accessed.

---

## Recovery

- [ ] Restore legitimate mailbox configuration.
- [ ] Re-enable the user only after identity security is validated.
- [ ] Require credential reset and authentication-factor verification.
- [ ] Confirm no unauthorized sessions remain.
- [ ] Increase monitoring of the affected identity.
- [ ] Validate that malicious rules and forwarding are removed.

---

## Post-Incident Actions

- [ ] Conduct root-cause analysis.
- [ ] Review password-spray detection coverage.
- [ ] Review authentication and MFA controls.
- [ ] Evaluate phishing-resistant MFA for high-risk users.
- [ ] Review mailbox-rule monitoring.
- [ ] Evaluate additional BEC detection logic.
- [ ] Conduct targeted security-awareness follow-up.
- [ ] Record lessons learned.
- [ ] Track remediation items to closure.

---

## Notes

Containment should prioritize stopping unauthorized access while preserving enough evidence to determine the cause, scope, and potential business impact of the incident.

Account recovery should not occur until authentication factors, active sessions, mailbox configuration, and related access have been reviewed.