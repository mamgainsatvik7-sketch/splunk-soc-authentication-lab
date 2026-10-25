# Splunk SOC Authentication Monitoring Lab

A hands-on Security Operations Center (SOC) investigation lab built with Splunk Enterprise and synthetic authentication logs. This project demonstrates authentication monitoring, SPL-based detection, suspicious login investigation, dashboard development, and incident reporting.

> **Project type:** Beginner cybersecurity portfolio project
> **Focus:** SOC Analyst Level 1 skills
> **Environment:** Windows 11 + Splunk Enterprise
> **Dataset:** 36 synthetic authentication events

## Table of Contents

* [Project Overview](#project-overview)
* [Objectives](#objectives)
* [Tools and Technologies](#tools-and-technologies)
* [Repository Structure](#repository-structure)
* [Dataset](#dataset)
* [Detection Rules](#detection-rules)
* [Dashboard](#dashboard)
* [Incident Investigation](#incident-investigation)
* [How to Reproduce the Lab](#how-to-reproduce-the-lab)
* [Skills Demonstrated](#skills-demonstrated)
* [Limitations](#limitations)
* [Future Improvements](#future-improvements)

## Project Overview

Authentication logs provide valuable evidence for identifying suspicious access patterns.

In this lab, I imported a synthetic authentication dataset into Splunk, wrote SPL searches to analyze login activity, investigated repeated authentication failures, created a monitoring dashboard, and documented an investigation involving the `admin` account.

The project follows a simplified SOC workflow:

**Log ingestion → Detection → Investigation → Evidence review → Incident reporting**

The objective is to demonstrate practical familiarity with SIEM searches and investigation workflows rather than claim detection of real-world attacks.

## Objectives

* Import and search authentication logs in Splunk.
* Analyze failed and successful login events.
* Identify accounts with repeated authentication failures.
* Detect successful logins following repeated failures.
* Investigate event sequences and timestamps.
* Build a dashboard for authentication monitoring.
* Document findings in an incident report.
* Publish reproducible detection logic and documentation on GitHub.

## Tools and Technologies

| Tool or Technology               | Purpose                                                     |
| -------------------------------- | ----------------------------------------------------------- |
| Splunk Enterprise                | Log ingestion, search, detection, and dashboard development |
| Search Processing Language (SPL) | Authentication event analysis and detection logic           |
| CSV                              | Synthetic authentication dataset                            |
| GitHub                           | Version control and portfolio publication                   |
| Markdown                         | Technical documentation and incident reporting              |
| Windows 11                       | Local lab environment                                       |

## Repository Structure

```text
splunk-soc-authentication-lab/
│
├── README.md
│
├── data/
│   ├── README.md
│   └── authentication_logs.csv
│
├── detections/
│   ├── README.md
│   ├── failed-login-threshold.spl
│   └── successful-login-after-failures.spl
│
├── incident-reports/
│   └── incident-report-admin-authentication.md
│
├── screenshots/
│   ├── dashboard-overview.png
│   ├── failed-logins-by-user.png
│   └── suspicious-login-patterns.png
│
└── documentation/
    └── investigation-findings.md
```

The `screenshots/` and `documentation/` directories are planned additions and may not yet exist in the repository.

## Dataset

The lab uses `data/authentication_logs.csv`, a synthetic dataset containing 36 authentication events.

### Fields

| Field        | Description                                  |
| ------------ | -------------------------------------------- |
| `timestamp`  | Timestamp associated with an event           |
| `username`   | Account associated with the event            |
| `source_ip`  | Recorded source IP address                   |
| `event_type` | Event category, such as login or logout      |
| `status`     | Event outcome                                |
| `host`       | Synthetic hostname associated with the event |

### Initial Dataset Summary

| Metric                                                                   | Observed Count |
| ------------------------------------------------------------------------ | -------------: |
| Failed events across the dataset                                         |             26 |
| Successful events across the dataset, including successful logout events |             10 |
| Successful login events                                                  |              7 |

These counts describe the dataset used during the investigation. They are not measurements of real-world attack activity.

## Detection Rules

### 1. Repeated Failed Login Attempts

**File:** `detections/failed-login-threshold.spl`

This detection groups failed authentication events by username and source IP address, then returns combinations with at least three failures.

```spl
index=main source="*authentication_logs.csv*" status=failure
| stats count AS failed_attempts BY username source_ip
| where failed_attempts >= 3
| sort - failed_attempts
```

**Observed results:**

| Username        | Failed Attempts |
| --------------- | --------------: |
| admin           |              11 |
| john            |               5 |
| alex            |               4 |
| guest           |               3 |
| service_account |               3 |

**Interpretation:** Repeated failures may indicate password guessing, misconfigured applications, or legitimate users entering incorrect credentials. Additional evidence is required to determine the cause.

### 2. Successful Login After Repeated Failures

**File:** `detections/successful-login-after-failures.spl`

This detection identifies successful login events associated with at least four failures in a rolling five-minute window for the same username and source IP address.

The rule uses `streamstats` to calculate the rolling failure count and returns successful events that meet the threshold.

**Observed results:**

| Username | Successful Login | Failures in the Applicable Window |
| -------- | ---------------- | --------------------------------: |
| admin    | 09:16:00         |                                10 |
| john     | 09:08:00         |                                 5 |
| alex     | 09:00:12         |                                 4 |

**Interpretation:** These events warrant investigation because a successful login followed repeated failures. The pattern alone does not establish account compromise.

## Dashboard

The Splunk dashboard is titled **SOC Authentication Monitoring**.

It contains four panels:

1. **Total Failed Logins** — displays the total number of failed login events.
2. **Failed Logins by Username** — compares failure counts across accounts.
3. **Successful Logins by Username** — summarizes successful login events.
4. **Suspicious Login Patterns** — displays successful logins preceded by repeated failures.

The dashboard provides a consolidated view of authentication activity and supports further investigation.

Screenshots will be added to the `screenshots/` directory after they have been captured and reviewed.

## Incident Investigation

**Incident ID:** SOC-001
**Incident type:** Suspicious Authentication Activity
**Provisional severity:** Medium
**Status:** Investigation in progress

### Key Findings

The `admin` account had 10 consecutive failed login attempts between 09:15:00 and 09:15:45, followed by a successful login at 09:16:00.

The failures occurred at five-second intervals. The successful login was recorded 15 seconds after the final failure.

### Assessment

The sequence is consistent with possible brute-force activity followed by successful authentication.

However, the dataset does not establish whether the login was legitimate or malicious. Account compromise remains unconfirmed.

### Recommended Follow-up

In a real SOC environment, the next steps would include reviewing MFA outcomes, validating the source and device, checking identity-provider logs, and investigating post-authentication activity.

The complete report is available at [`incident-reports/incident-report-admin-authentication.md`](incident-reports/incident-report-admin-authentication.md).

## How to Reproduce the Lab

### Prerequisites

* Windows 11 or a compatible operating system.
* Splunk Enterprise.
* Access to the repository files.

### Steps

1. Download or clone this repository.
2. Review `data/README.md` and inspect `data/authentication_logs.csv`.
3. Open Splunk and navigate to Search & Reporting.
4. Import the CSV into the `main` index.
5. Confirm that the dataset returns 36 events.
6. Open the `.spl` files in `detections/`.
7. Run each detection query in Splunk.
8. Compare your results with the documented findings.
9. Create or review the SOC Authentication Monitoring dashboard.
10. Follow the investigation documented in the incident report.

**Note:** The queries assume the imported events are in `index=main` and that the source field matches `*authentication_logs.csv*`. Adjust the search if your Splunk ingestion settings differ.

## Skills Demonstrated

This project provides practical evidence of work with:

* SIEM log ingestion and searching.
* Basic SPL query construction.
* Event filtering, aggregation, and sorting.
* Rolling time-window analysis.
* Authentication anomaly identification.
* Investigation timelines and event correlation.
* Dashboard creation.
* Incident documentation.
* GitHub repository organization.
* Communicating findings and analytical limitations.

## Limitations

This is a learning project, not a production detection system.

* All events are synthetic.
* The dataset contains only 36 events.
* The documentation-reserved IP address `203.0.113.25` is an example and is not evidence of a real attacker.
* The dataset contains no ground-truth labels identifying malicious activity.
* MFA outcomes, endpoint telemetry, session data, and post-authentication behavior are unavailable.
* A detection match is an investigative lead, not proof of compromise.
* The rules have been tested against this small dataset and have not been validated against a production environment.
* The dashboard and detections do not establish the effectiveness of a real-world SOC monitoring program.

## Future Improvements

Potential extensions include:

* Add more varied synthetic authentication scenarios.
* Test detection thresholds against additional benign and suspicious patterns.
* Investigate multiple source IP addresses and distributed failures.
* Improve event normalization and timestamp handling.
* Add investigation findings and dashboard screenshots.
* Explore alerting and scheduled searches.
* Document false-positive considerations and detection tuning.
* Add tests that verify expected detection results.

---

**Project status:** Core Splunk searches, dashboard panels, and the initial incident investigation are complete. Repository documentation and portfolio presentation are being finalized.
## Dashboard and Detection Screenshots

### SOC Authentication Monitoring Dashboard

The dashboard summarizes failed logins, successful logins, and suspicious authentication patterns.

![SOC Authentication Monitoring Dashboard](screenshots/dashboard-overview.png)

### Failed Logins by Username

This detection identifies accounts with repeated authentication failures. In this sample dataset, the `admin` account had the highest number of failed login attempts.

![Failed Logins by Username](screenshots/failed-logins-by-user.png)

### Suspicious Login Patterns

This detection highlights successful login events preceded by repeated failures within a five-minute window. These patterns warrant investigation but do not independently confirm account compromise.

![Suspicious Login Patterns](screenshots/suspicious-login-patterns.png)

