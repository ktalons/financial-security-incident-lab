# Incident Evidence

## Incident Classification

**Type:** Account Takeover / Business Email Compromise  
**Severity:** Critical  
**Confidence:** High

---

## Affected Identity

- User: `j.smith@summitcu.example`
- Normal source IP: `198.51.100.24`
- Suspicious source IP: `203.0.113.50`

---

## Key Evidence

### Password Spray

The source IP `203.0.113.50` generated failed authentication attempts against five unique identities.

Affected identities:

- `a.lee@summitcu.example`
- `j.smith@summitcu.example`
- `m.garcia@summitcu.example`
- `r.patel@summitcu.example`
- `s.williams@summitcu.example`

Detection severity:

**Medium**

> The password spray is suspicious independently but does not by itself confirm account compromise.

---

### Successful Authentication After Failures

The affected identity successfully authenticated from the same source responsible for the password spray.

User:

`j.smith@summitcu.example`

Source:

`203.0.113.50`

Detection severity:

**High**

> This event significantly increases confidence that valid credentials were obtained.

---

### External Mail Forwarding

An external forwarding rule was created for the affected mailbox.

Destination:

`collections@external-mail.example`

Detection severity:

**High**

> External mailbox forwarding may provide an attacker continued access to communications even after the original authentication session ends.

---

### Suspicious Inbox Rule

A mailbox rule was created to move messages containing:

`Payment` to deleted items.

Detection severity:

**High**

> The behavior is consistent with an attempt to conceal responses associated with fraudulent payment activity.

---

### Suspicious Payment Email

A message with the subject:

`Updated Payment Instructions`

was sent to:

- `finance@summitcu.example`
- `accounts.payable@summitcu.example`

Detection severity:

**High**

> This behavior is consistent with a BEC scenario involving attempted manipulation of financial processes.

---

## Correlated Incident

The detection engine correlated:

- Password spraying
- Successful authentication after failures
- External mailbox forwarding

into the following incident:

```text
Type: account_takeover_bec
Severity: Critical
Confidence: High
```

### Correlation Rationale

> Each individual event has legitimate or ambiguous explanations when considered independently. The combination of authentication abuse, successful account access, and mailbox manipulation from the same source substantially increases confidence that account takeover occurred.

---

## Evidence Integrity

All evidence used in this project is synthetic.

The following reserved resources are intentionally used:

- `.example` domains
- RFC 5737 documentation IP address ranges

<sub>No production data, credentials, real users, or real financial institution infrastructure are represented.</sub>
