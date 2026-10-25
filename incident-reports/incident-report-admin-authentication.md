# Incident Report: Suspicious Admin Authentication Activity

## 1. Incident Information

| Field                | Details                            |
| -------------------- | ---------------------------------- |
| Incident ID          | SOC-001                            |
| Incident Type        | Suspicious Authentication Activity |
| Severity             | Medium — provisional               |
| Status               | Investigation in progress          |
| Environment          | Synthetic Splunk SOC lab           |
| Data Source          | `authentication_logs.csv`          |
| Account Investigated | `admin`                            |

## 2. Executive Summary

An investigation of synthetic authentication logs identified repeated failed login attempts against the `admin` account, followed by a successful login.

Ten consecutive failed login attempts occurred between 09:15:00 and 09:15:45 at five-second intervals. A successful login was recorded at 09:16:00, 15 seconds after the final failure.

This pattern is consistent with possible brute-force activity followed by successful authentication. However, the available evidence does not establish whether the successful login was legitimate or whether the account was compromised.

## 3. Evidence and Timeline

| Time              | Event            | Observation                                        |
| ----------------- | ---------------- | -------------------------------------------------- |
| 09:15:00          | Failed login     | First failure in the initial burst                 |
| 09:15:05–09:15:40 | Failed logins    | Eight additional failures at five-second intervals |
| 09:15:45          | Failed login     | Tenth consecutive failure                          |
| 09:16:00          | Successful login | Recorded 15 seconds after the final failure        |
| 09:55:00          | Failed login     | Additional failure recorded later                  |

The dataset contains 12 recorded events associated with the `admin` account.

**Important:** The times above are the event times recorded in the synthetic dataset. No date or timezone is inferred here.

## 4. Detection Logic

The investigation used SPL searches to:

1. Retrieve authentication events associated with `admin`.
2. Sort events chronologically.
3. Calculate the intervals between consecutive failed logins.
4. Identify a successful login following repeated failures.
5. Compare detection behavior across five-minute and 15-second rolling windows.

The five-minute detection identified the successful login following ten failures. The shorter-window test did not flag this event because the final failure occurred at the 15-second boundary.

## 5. Assessment

**Finding:** Suspicious authentication pattern identified.

**Assessment:** The rapid sequence of failed logins followed by a successful login warrants further investigation.

**Confidence:** The event sequence is directly observable in the synthetic data. The cause of the failures and the legitimacy of the successful login remain undetermined.

**Compromise status:** Unconfirmed.

## 6. Recommended Investigation Actions

In a real environment, a SOC analyst should:

1. Validate the activity against the identity provider or authentication server logs.
2. Determine whether the successful login originated from an expected device, location, and source IP.
3. Review MFA outcomes and authentication methods.
4. Check for additional failed or successful logins involving the account.
5. Review post-authentication activity, including privilege changes and access to sensitive resources.
6. Follow the organization's incident response procedures if additional evidence indicates compromise.

Containment actions should follow the organization's authorization and escalation procedures.

## 7. Data Limitations

* All authentication events are synthetic.
* The dataset contains only 36 events.
* The IP address `203.0.113.25` belongs to a documentation-reserved range and is not evidence of a real attacker.
* The dataset does not provide MFA outcomes, endpoint telemetry, session activity, or post-authentication behavior.
* No ground-truth labels establish which successful logins are legitimate or malicious.
* The severity is provisional and intended for this training scenario.

## 8. Conclusion

The lab demonstrates how Splunk can be used to identify repeated authentication failures, detect a subsequent successful login, investigate event timing, and document findings.

The evidence supports further investigation of the observed pattern but does not prove a real attack or account compromise.
