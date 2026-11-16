"""Educational SOC log analyzer for synthetic authentication CSV records."""

import csv
from datetime import datetime, timedelta
from pathlib import Path

# 1. File locations and detection settings
project_folder = Path(__file__).resolve().parent
input_file = project_folder / "server_logs.csv"
output_folder = project_folder / "output"
output_folder.mkdir(parents=True, exist_ok=True)

threshold = 3
time_window = timedelta(minutes=5)
time_format = "%Y-%m-%d %H:%M:%S"
security_keywords = ["failed login", "suspicious", "unusual traffic", "security breach"]

# 2. Collect log events
warning_count = 0
error_count = 0
security_alerts = []
failed_logins = {}
login_attempts = {}
successful_logins = {}

with open(input_file, "r", newline="", encoding="utf-8-sig") as file:
    reader = csv.DictReader(file)
    required_columns = {"timestamp", "level", "message", "username", "source_ip"}
    if not required_columns.issubset(reader.fieldnames or []):
        raise ValueError("Input CSV must contain: " + ", ".join(sorted(required_columns)))

    for row in reader:
        level = row["level"].strip().upper()
        message = row["message"].lower()
        username = row["username"].strip()
        source_ip = row["source_ip"].strip()

        if level == "WARNING":
            warning_count += 1

            if "failed login attempt for user" in message:
                if username:
                    failed_logins[username] = failed_logins.get(username, 0) + 1

                if username and source_ip:
                    timestamp = datetime.strptime(row["timestamp"], time_format)
                    key = (username, source_ip)
                    login_attempts.setdefault(key, []).append(timestamp)

            if any(keyword in message for keyword in security_keywords):
                security_alerts.append(row)

        elif level == "ERROR":
            error_count += 1

        elif level == "INFO" and "logged in" in message:
            if username and source_ip:
                timestamp = datetime.strptime(row["timestamp"], time_format)
                key = (username, source_ip)
                successful_logins.setdefault(key, []).append(timestamp)

# 3. Save keyword-matched warning events
with open(output_folder / "security_alerts.csv", "w", newline="", encoding="utf-8") as file:
    fieldnames = ["timestamp", "level", "message", "username", "source_ip"]
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(security_alerts)

print("\n--- LOG ANALYSIS SUMMARY ---")
print("Total WARNING events:", warning_count)
print("Total ERROR events:", error_count)
print("Potential security alerts:", len(security_alerts))
print("\n--- FAILED LOGIN SUMMARY ---")
for username, count in failed_logins.items():
    print(f"{username}: {count} failed attempts")

# 4. Detect at least 3 failures within a moving 5-minute window
brute_force_alerts = []
print("\n--- BRUTE-FORCE DETECTION ---")

for (username, source_ip), timestamps in login_attempts.items():
    timestamps.sort()

    for i in range(len(timestamps) - threshold + 1):
        first_attempt = timestamps[i]
        last_attempt = timestamps[i + threshold - 1]

        if last_attempt - first_attempt <= time_window:
            brute_force_alerts.append({
                "username": username,
                "source_ip": source_ip,
                "failed_attempts": threshold,
                "start_time": first_attempt.strftime(time_format),
                "end_time": last_attempt.strftime(time_format),
                "severity": "MEDIUM",
                "reason": f"{threshold} failed login attempts within {time_window}"
            })
            print(f"Potential brute force: {username} from {source_ip}")
            break  # One brute-force alert per account/IP pair

with open(output_folder / "brute_force_alerts.csv", "w", newline="", encoding="utf-8") as file:
    fieldnames = ["username", "source_ip", "failed_attempts", "start_time",
                  "end_time", "severity", "reason"]
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(brute_force_alerts)

# 5. Detect successful login after at least 3 recent failures
compromise_alerts = []
high_windows = []  # Internal evidence for correlating related alerts
print("\n--- FAILED LOGIN FOLLOWED BY SUCCESS ---")

for key, success_times in successful_logins.items():
    if key not in login_attempts:
        continue

    username, source_ip = key
    failed_times = sorted(login_attempts[key])

    for success_time in sorted(success_times):
        recent_failures = [
            t for t in failed_times
            if t < success_time and success_time - t <= time_window
        ]

        if len(recent_failures) >= threshold:
            compromise_alerts.append({
                "username": username,
                "source_ip": source_ip,
                "failed_attempts": len(recent_failures),
                "success_time": success_time.strftime(time_format),
                "severity": "HIGH",
                "reason": (
                    f"Successful login after {len(recent_failures)} "
                    f"failed attempts within {time_window}"
                )
            })
            # Retain the actual failures responsible for this HIGH alert.
            high_windows.append((key, recent_failures))
            print(f"Failed logins followed by success: {username} from {source_ip}")

with open(output_folder / "compromise_alerts.csv", "w", newline="", encoding="utf-8") as file:
    fieldnames = ["username", "source_ip", "failed_attempts", "success_time",
                  "severity", "reason"]
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(compromise_alerts)

# 6. Correlate overlapping detections into SOC cases
# Keep BOTH evidence reports, but omit a MEDIUM alert from the consolidated
# report when its failure sequence is included in a HIGH detection for the
# same username AND source IP. Shared IP alone is never enough to merge.
soc_alerts = []

for alert in compromise_alerts:
    soc_alerts.append({
        "alert_type": "Failed Logins Followed by Success",
        "username": alert["username"],
        "source_ip": alert["source_ip"],
        "severity": alert["severity"],
        "timestamp": alert["success_time"],
        "reason": alert["reason"]
    })

for alert in brute_force_alerts:
    key = (alert["username"], alert["source_ip"])
    first_attempt = datetime.strptime(alert["start_time"], time_format)
    last_attempt = datetime.strptime(alert["end_time"], time_format)

    # The brute-force window is correlated only when its actual boundary
    # events belong to the same set of failures preceding a HIGH alert.
    correlated = any(
        high_key == key
        and first_attempt in failure_times
        and last_attempt in failure_times
        for high_key, failure_times in high_windows
    )

    if correlated:
        print(f"Correlated MEDIUM into HIGH case: {key[0]} from {key[1]}")
        continue

    soc_alerts.append({
        "alert_type": "Potential Brute Force",
        "username": alert["username"],
        "source_ip": alert["source_ip"],
        "severity": alert["severity"],
        "timestamp": alert["end_time"],
        "reason": alert["reason"]
    })

# 7. Sort consolidated cases: HIGH first, then most recent
severity_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
soc_alerts.sort(
    key=lambda alert: (severity_rank[alert["severity"]], alert["timestamp"]),
    reverse=True
)

for number, alert in enumerate(soc_alerts, start=1):
    alert["incident_id"] = f"INC-{number:03d}"
    alert["status"] = "OPEN"  # Demo status; not persisted between runs

    if alert["alert_type"] == "Potential Brute Force":
        alert["recommended_action"] = (
            "Review failed login events and investigate the source IP address."
        )
    else:
        alert["recommended_action"] = (
            "Verify whether the successful login was authorized and "
            "review subsequent account activity."
        )

with open(output_folder / "soc_alert_report.csv", "w", newline="", encoding="utf-8") as file:
    fieldnames = ["incident_id", "alert_type", "username", "source_ip",
                  "severity", "timestamp", "reason", "status", "recommended_action"]
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(soc_alerts)

# 8. Summarize unique consolidated alert records
high_count = sum(alert["severity"] == "HIGH" for alert in soc_alerts)
medium_count = sum(alert["severity"] == "MEDIUM" for alert in soc_alerts)
low_count = sum(alert["severity"] == "LOW" for alert in soc_alerts)
open_count = sum(alert["status"] == "OPEN" for alert in soc_alerts)
total_alerts = len(soc_alerts)

summary = (
    "--- SOC SHIFT SUMMARY ---\n"
    f"Total alerts: {total_alerts}\n"
    f"HIGH severity: {high_count}\n"
    f"MEDIUM severity: {medium_count}\n"
    f"LOW severity: {low_count}\n"
    f"OPEN alerts: {open_count}\n"
)
print("\n" + summary)

with open(output_folder / "shift_summary.txt", "w", encoding="utf-8") as file:
    file.write(summary)

print("All security reports generated successfully.")
print("Reports saved in:", output_folder)
