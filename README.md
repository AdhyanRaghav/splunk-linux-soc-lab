# Splunk Linux SOC Home Lab

A hands-on Security Operations Center (SOC) home lab built using **Splunk Enterprise** to collect, monitor, analyze, and investigate Linux authentication events. This project focuses on identifying suspicious login activity, detecting repeated authentication failures, and developing practical SOC investigation skills using Search Processing Language (SPL).

## Overview

This project simulates a basic SOC monitoring environment using Linux authentication logs as a source of security telemetry.

The objective is to build a practical understanding of how security analysts use SIEM platforms to identify suspicious activity, investigate authentication-related events, and monitor potential security incidents.

## Objectives

- Collect and analyze Linux authentication logs.
- Monitor failed authentication attempts.
- Identify targeted user accounts.
- Detect repeated authentication failures.
- Analyze authentication activity over time.
- Investigate security events using raw logs and extracted fields.
- Build visualizations for security monitoring.

## Tools & Technologies

| Tool | Purpose |
|---|---|
| Splunk Enterprise | SIEM platform and log analysis |
| Linux (Zorin OS) | Host environment and log source |
| SPL | Searching, filtering, and analyzing events |
| Linux Authentication Logs | Security event data |
| Dashboard Studio | Security monitoring and visualization |

## Dashboard

The **Linux Authentication Monitoring** dashboard provides an overview of authentication-related activity.

### Dashboard Panels

- **Failed Logins** – Displays the total number of authentication failure events identified.
- **Targeted Accounts** – Identifies the number of distinct accounts appearing in the analyzed authentication failures.
- **Repeated Account Failures** – Highlights accounts with multiple failure events based on the current detection threshold.
- **Authentication Failure Timeline** – Visualizes authentication failure activity over time.
- **Failure Events by Username** – Shows the distribution of failure events across usernames.
- **Authentication Failures by Host** – Displays authentication failure activity by host.
- **Authentication Investigation Table** – Provides event-level information for further investigation.

## Dashboard Preview

Screenshots of the dashboard are available in the [`screenshots/`](screenshots/) directory.

## Detection & Analysis

The lab uses SPL queries to investigate Linux authentication activity.

### 1. Authentication Failure Monitoring

Searches authentication logs for common failure indicators.

```spl
index="linux_auth" ("authentication failure" OR "password check failed" OR "Failed password")
| stats count
```

### 2. Identifying Targeted Accounts

Extracts usernames from authentication failure events and identifies distinct accounts.

```spl
index="linux_auth" ("authentication failure" OR "password check failed" OR "Failed password")
| rex "user \((?<username>[^\)]+)\)"
| rex "logname=(?<username2>[^\s]+)"
| eval username=coalesce(username,username2)
| stats dc(username) AS targeted_accounts
```

### 3. Repeated Authentication Failures

Groups failure events by username and identifies accounts with multiple failure events.

```spl
index="linux_auth" ("authentication failure" OR "password check failed" OR "Failed password")
| rex "user \((?<username>[^\)]+)\)"
| rex "logname=(?<username2>[^\s]+)"
| eval username=coalesce(username,username2)
| stats count by username
| where count >= 2
| stats count AS accounts_with_repeated_failures
```

> Note: These searches currently analyze authentication failure-related log events. Multiple log entries may correspond to a single underlying login attempt, so event counts should be interpreted with context during investigation.

## Investigation Workflow

The investigation workflow follows a basic SOC analysis process:

1. **Monitor** – Observe authentication activity through the dashboard.
2. **Identify** – Look for abnormal failure patterns and repeatedly targeted accounts.
3. **Analyze** – Review usernames, hosts, timestamps, authentication services, and raw log events.
4. **Investigate** – Correlate related log entries to understand what occurred.
5. **Document** – Record findings and relevant evidence.

## Skills Demonstrated

- SIEM fundamentals
- Log ingestion and analysis
- SPL (Search Processing Language)
- Linux authentication log analysis
- Security event investigation
- Username and host identification
- Detection logic development
- Dashboard creation and data visualization
- SOC investigation workflow

## Project Status

**Current phase:** Initial monitoring and investigation capabilities implemented.

Implemented:
- Linux authentication log ingestion into Splunk
- Authentication failure searches
- Username identification
- Repeated failure analysis
- Time-based authentication monitoring
- Host-based monitoring
- Investigation table
- Monitoring dashboard

Planned improvements:
- Refine authentication event classification
- Improve detection accuracy and reduce duplicate event counting
- Develop time-window-based detection logic
- Implement automated alerts
- Simulate controlled suspicious authentication activity
- Expand monitoring to additional Linux security events
- Document investigation case studies

## Disclaimer

This project is intended for educational purposes and is conducted within a controlled home lab environment. The detection logic is experimental and should not be considered a production-ready security monitoring solution.

---

**Author:** Adhyan Raghav  
**Domain:** Cybersecurity | Security Operations | SIEM  
