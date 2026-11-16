# Security Log Analyzer

A Python tool that reads simulated server authentication logs, detects suspicious login activity, and generates SOC-style alert reports.

I built this project to practice log analysis, brute-force detection, alert correlation, and incident reporting. It is modeled on the kind of monitoring and triage work done in a Security Operations Center (SOC).

## Features

- **Log analysis.** Reads CSV server logs and counts WARNING and ERROR events.
- **Security event filtering.** Flags WARNING events containing security keywords such as `failed login`, `suspicious`, `unusual traffic` and `security breach`.
- **Failed login monitoring.** Tracks failed login attempts per user.
- **Brute-force detection (MEDIUM).** Three or more failed logins for the same username from the same IP within five minutes.
- **Suspicious success detection (HIGH).** A successful login that follows three or more failures from the same username and IP within the previous five minutes.
- **Alert correlation.** Merges overlapping MEDIUM and HIGH detections into a single case so one login sequence does not create duplicate incidents.
- **Incident reporting.** Produces incident IDs, statuses, recommended actions and a consolidated SOC report.
- **Shift summary.** Summarizes alert counts by severity and status.

## Technologies

- Python 3.10.4
- Standard library only (`csv`, `datetime`, `pathlib`), with no packages to install

## Project Structure

```text
security_log_analyzer/
├── analyzer.py
├── server_logs.csv
├── README.md
└── output/
    ├── security_alerts.csv
    ├── brute_force_alerts.csv
    ├── compromise_alerts.csv
    ├── soc_alert_report.csv
    └── shift_summary.txt
```

The `output` folder is created automatically on the first run, and its files are overwritten on every run.

## Input Format

The script reads `server_logs.csv` from the same folder as `analyzer.py`. The file must have a header row with these columns, otherwise the script stops with an error.

| Column | Description |
|---|---|
| `timestamp` | Format `YYYY-MM-DD HH:MM:SS` |
| `level` | `INFO`, `WARNING` or `ERROR` (case-insensitive) |
| `message` | Free-text log message |
| `username` | Account name (may be blank) |
| `source_ip` | Source IP address (may be blank) |

Example rows (illustrative format only)

```csv
timestamp,level,message,username,source_ip
2026-01-10 09:00:05,WARNING,Failed login attempt for user admin,admin,192.0.2.10
2026-01-10 09:00:40,WARNING,Failed login attempt for user admin,admin,192.0.2.10
2026-01-10 09:01:15,WARNING,Failed login attempt for user admin,admin,192.0.2.10
2026-01-10 09:02:00,INFO,User admin logged in,admin,192.0.2.10
```

### Message wording matters

Detection depends on specific phrases in the `message` field (case-insensitive).

- A failed attempt is a **WARNING** row whose message contains `failed login attempt for user`.
- A successful login is an **INFO** row whose message contains `logged in`.

If your logs word these events differently, the brute-force and compromise detections will find nothing and will not warn you. Change the phrases in `analyzer.py` to match your data.

Rows with a blank username or source IP are still counted in the WARNING and ERROR totals, but they are excluded from the IP-based detections.

## How to Run

1. Make sure Python 3 is installed.
2. Clone or download the repository.
3. The repository includes a sample `server_logs.csv`. To analyze your own data, replace it with a file in the format described under Input Format.
4. Open a terminal in the project folder and run the command below.

```bash
python analyzer.py
```

The script prints a summary to the console and saves all reports to the `output` folder.

## How It Works

### 1. Log Processing

Each row is read and its level and message are normalized. WARNING and ERROR events are counted. WARNING events containing a security keyword are saved to `security_alerts.csv`. Note that every failed-login warning contains the keyword `failed login`, so these always count as keyword matches.

### 2. Brute-Force Detection

Failed logins are grouped by `(username, source_ip)` and sorted by time. A sliding window checks whether any run of three consecutive failures starts and ends within five minutes (inclusive). If so, a MEDIUM alert is raised. Only one brute-force alert is created per username and IP pair per run.

### 3. Failed Logins Followed by Success

For every successful login, the script counts failures from the same username and IP that happened before it, within the previous five minutes. If there are three or more, a HIGH alert is raised, because this can indicate a successful password-guessing attempt. This pattern alone does not confirm a compromised account. Each qualifying successful login creates its own alert.

### 4. Alert Correlation

During testing I noticed that the same login sequence could produce both a MEDIUM brute-force alert and a HIGH failed-login-then-success alert, which would send an analyst to investigate one event twice.

To fix this, a MEDIUM alert is left out of the consolidated report when both its first and last failure timestamps belong to the failure set behind a HIGH alert for the same username and the same source IP. A shared IP alone never causes a merge. The original detections stay in their own CSV files, so no evidence is lost.

### 5. SOC Reporting

Consolidated cases are sorted by severity (HIGH first) and then by timestamp (most recent first). Incident IDs (`INC-001`, `INC-002`, and so on) are assigned after sorting, and every case starts with the status `OPEN`. Each case gets a recommended action based on its type.

## Output Files

The `output` folder in this repository contains the reports generated from the included sample data, so you can inspect the results without running the script.

| File | Contents |
|---|---|
| `security_alerts.csv` | WARNING rows that matched a security keyword |
| `brute_force_alerts.csv` | MEDIUM alerts with username, IP, window start and end, and reason |
| `compromise_alerts.csv` | HIGH alerts with username, IP, failure count, success time and reason |
| `soc_alert_report.csv` | Consolidated cases with incident ID, alert type, severity, timestamp, reason, status and recommended action |
| `shift_summary.txt` | Alert counts by severity and by OPEN status |

In `brute_force_alerts.csv`, the `failed_attempts` column records the detection threshold (3), not the total number of failures in the window. In `compromise_alerts.csv` it records the actual number of failures before the successful login.

## Configuration

Detection settings are constants at the top of `analyzer.py`.

| Variable | Default | Purpose |
|---|---|---|
| `threshold` | `3` | Failures needed to trigger an alert |
| `time_window` | 5 minutes | Window used by both detections |
| `time_format` | `%Y-%m-%d %H:%M:%S` | Expected timestamp format |
| `security_keywords` | see script | Keywords for the WARNING filter |

The message phrases described under Input Format are written directly in the script.

## Results

I tested the analyzer on a synthetic dataset of 73 server log entries containing normal activity, failed logins and successful authentications.

### Log Analysis Summary

| Metric | Result |
|---|---:|
| Total WARNING events | 17 |
| Total ERROR events | 6 |
| Security-related keyword matches | 16 |
| Failed login attempts for admin | 7 |
| Failed login attempts for guest | 5 |

### Detection Results

| Detection Type | Raw Alerts |
|---|---:|
| Potential Brute Force | 2 |
| Failed Logins Followed by Success | 1 |

After correlation, the consolidated report contains two cases instead of three separate alerts.

| Incident ID | Alert Type | Source IP | Severity | Status |
|---|---|---|---|---|
| INC-001 | Failed Logins Followed by Success | 192.0.2.10 | HIGH | OPEN |
| INC-002 | Potential Brute Force | 192.0.2.50 | MEDIUM | OPEN |

### SOC Shift Summary

```text
--- SOC SHIFT SUMMARY ---
Total alerts: 2
HIGH severity: 1
MEDIUM severity: 1
LOW severity: 0
OPEN alerts: 2
```

## Testing

I tested the program with these simulated scenarios.

- Multiple failed logins within five minutes
- Failed logins spread over longer periods
- Successful logins following repeated failures
- Successful logins outside the detection window
- Login attempts from different source IPs
- A CSV file containing only column headers, which produces zero alerts without crashing

These tests verified the core detection and correlation logic. There is no automated test suite yet.

## Limitations

- Works on simulated CSV files only, not live server or SIEM data.
- Detection depends on fixed message phrases, keywords and thresholds. Logs worded differently produce no alerts.
- A malformed timestamp on a failed-login or successful-login row stops the script instead of skipping the row.
- Only one brute-force alert is created per username and IP pair per run.
- Detection is per username and IP pair, so distributed attacks, password spraying and slow attacks are not detected.
- Events with a missing username or source IP are excluded from the IP-based detections.
- The per-user failed login summary printed to the console combines all source IPs.
- The LOW severity level exists in the report format, but no detection currently produces it.
- Incident IDs and statuses are regenerated on every run and are not saved.
- The tool cannot confirm whether activity is actually malicious.
- Correlation only merges overlapping detections and is not full incident management.

## Future Improvements

- Accept thresholds, time windows and message patterns through command-line arguments or a config file.
- Analyze real Windows Security Event Logs.
- Add detection for password spraying and logins from unusual locations.
- Add unit tests with sample log fixtures.
- Persist incident status between runs.
- Build a simple dashboard for alert visualization.
- Explore integration with SIEM platforms such as Wazuh or Splunk.

## Disclaimer

This is an educational cybersecurity project built with synthetic log data. It demonstrates basic security monitoring and rule-based detection concepts and is not a replacement for a production security monitoring system.
