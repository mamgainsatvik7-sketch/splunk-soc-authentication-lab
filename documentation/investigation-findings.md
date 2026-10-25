# Authentication Monitoring — Investigation Findings

## 1. Investigation Overview

**Project:** Splunk SOC Authentication Monitoring Lab
**Investigation ID:** SOC-001
**Platform:** Splunk Enterprise
**Dataset:** Synthetic authentication logs
**Status:** Investigation completed for the available sample data
**Assessment:** Suspicious authentication activity detected; account compromise unconfirmed.

## 2. Objectives

* Identify repeated failed login attempts.
* Determine which usernames experienced the most failures.
* Detect successful logins following repeated authentication failures.
* Investigate the suspicious authentication sequence involving the admin account.
* Document findings, limitations, and recommended follow-up actions.

## 3. Dataset Summary

The dataset contains 36 synthetic authentication events.

The analysis identified:

* 26 failed events.
* 10 successful events, including successful logout events.
* 7 successful login events.

These categories describe the supplied sample dataset and should not be interpreted as measurements of activity in a real production environment.

## 4. Detection 1 — Repeated Failed Logins

### Objective

Identify usernames with three or more failed events from the same source IP.

### Results

| Username        | Failed attempts |
| --------------- | --------------: |
| admin           |              11 |
| john            |               5 |
| alex            |               4 |
| guest           |               3 |
| service_account |               3 |

### Interpretation

The admin account had the highest number of failed login attempts. Repeated failures may indicate mistyped credentials, automated password guessing, or another authentication problem.

These results justify further investigation but do not independently establish malicious intent.

## 5. Detection 2 — Successful Login Following Repeated Failures

### Objective

Identify successful login events preceded by at least four failed login events for the same username and source IP within a five-minute window.

### Findings

The query identified suspicious successful login events involving:

* **admin:** A successful login following a sequence of repeated failures.
* **john:** A successful login following repeated failures.
* **alex:** A successful login following repeated failures.

### Interpretation

A successful authentication following repeated failures can be consistent with a brute-force attempt that eventually succeeds. However, the same pattern can also occur when a legitimate user repeatedly enters an incorrect password.

Additional evidence is required to determine whether any of these events resulted from an attack.

## 6. Admin Account Investigation

The admin account had 12 recorded events:

* Ten consecutive failed login attempts between 09:15:00 and 09:15:45, at five-second intervals.
* One successful login at 09:16:00, 15 seconds after the final failure.
* One later failed login at 09:55:00.

The associated source IP in the sample was `203.0.113.25`.

### Assessment

The rapid sequence of failures followed by a successful login is suspicious and warrants investigation. The timing is consistent with repeated authentication attempts followed by successful authentication.

The IP address belongs to a range reserved for documentation and examples. It does not establish the presence of a real attacker.

**Conclusion:** Potentially suspicious authentication activity was identified. Account compromise is not confirmed.

## 7. Recommended SOC Follow-Up

If this pattern appeared in a real environment, a SOC analyst should:

1. Review authentication events before and after the suspicious sequence.
2. Verify whether the source IP and login activity are expected.
3. Check MFA results and authentication method details.
4. Correlate the activity with endpoint, VPN, identity-provider, and other available security logs.
5. Review subsequent account activity for unauthorized access or privilege changes.
6. Escalate to the incident response team if corroborating evidence indicates compromise.
7. Follow the organization's approved account-containment procedures if compromise is confirmed or urgent risk warrants action.

## 8. Limitations

* The dataset is synthetic and contains only 36 events.
* No production environment was monitored.
* MFA, endpoint telemetry, session information, and post-authentication activity are unavailable.
* The dataset has no ground-truth labels identifying confirmed attacks.
* Detection thresholds are initial rules for this lab, not universally appropriate production settings.
* The detections identify suspicious patterns, not confirmed incidents.

## 9. Skills Demonstrated

* Splunk Search Processing Language (SPL).
* Authentication log analysis.
* Failed-login threshold detection.
* Time-window-based event correlation.
* Suspicious login investigation.
* Evidence-based incident documentation.
* Security monitoring dashboard creation.

## 10. Final Conclusion

This project demonstrates a basic SOC investigation workflow using Splunk: ingest authentication data, develop detection searches, identify suspicious patterns, examine relevant events, visualize results, and document findings.

The investigation identified authentication sequences requiring further review. Because the evidence is synthetic and lacks corroborating telemetry, the results should be described as suspicious activity rather than a confirmed account compromise.
