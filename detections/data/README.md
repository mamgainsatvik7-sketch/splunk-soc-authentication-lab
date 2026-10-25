# Authentication Dataset

This directory contains the synthetic authentication dataset used in the Splunk SOC Authentication Monitoring Lab.

## Dataset Details

* **Filename:** `authentication_logs.csv`
* **Event count:** 36
* **Format:** CSV
* **Purpose:** Practice authentication log analysis and detection engineering.

## Fields

| Field        | Description                                  |
| ------------ | -------------------------------------------- |
| `timestamp`  | Time of the authentication event             |
| `username`   | Account associated with the event            |
| `source_ip`  | Source IP address recorded in the event      |
| `event_type` | Type of event, such as login or logout       |
| `status`     | Event outcome                                |
| `host`       | Synthetic hostname associated with the event |

## Important Limitations

The dataset is synthetic and is not evidence of real-world malicious activity. IP addresses reserved for documentation are used as examples.

No real customer logs or credentials should be included.
