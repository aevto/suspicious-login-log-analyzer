from flask import Flask, render_template, request
import re
from collections import Counter, defaultdict

app = Flask(__name__)

FAILED_KEYWORDS = [
    "failed password",
    "invalid user",
    "authentication failure",
    "login failed",
    "failed login"
]

SUCCESS_KEYWORDS = [
    "accepted password",
    "login successful",
    "authentication successful",
    "session opened"
]

COMMON_USERNAMES = [
    "root", "admin", "administrator", "test", "guest", "user", "ubuntu"
]

IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
TIME_REGEX = r"\b([01]\d|2[0-3]):([0-5]\d):([0-5]\d)\b"


def extract_ip(line):
    match = re.search(IP_REGEX, line)
    return match.group(0) if match else None


def extract_time_parts(line):
    match = re.search(TIME_REGEX, line)
    if match:
        return int(match.group(1)), int(match.group(2)), int(match.group(3))
    return None


def extract_seconds_of_day(line):
    parts = extract_time_parts(line)
    if not parts:
        return None
    h, m, s = parts
    return h * 3600 + m * 60 + s


def extract_hour(line):
    parts = extract_time_parts(line)
    if parts:
        return parts[0]
    return None


def extract_username(line):
    patterns = [
        r"for\s+([a-zA-Z0-9_\-\.]+)\s+from",
        r"user=([a-zA-Z0-9_\-\.]+)",
        r"invalid user\s+([a-zA-Z0-9_\-\.]+)",
        r"username\s*[:=]\s*([a-zA-Z0-9_\-\.]+)"
    ]
    for pattern in patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def is_failed_login(line):
    lower = line.lower()
    return any(keyword in lower for keyword in FAILED_KEYWORDS)


def is_success_login(line):
    lower = line.lower()
    return any(keyword in lower for keyword in SUCCESS_KEYWORDS)


def detect_bursts(failed_attempts_by_ip, threshold=3, window_seconds=60):
    bursts = []

    for ip, attempts in failed_attempts_by_ip.items():
        times = sorted([a["time"] for a in attempts if a["time"] is not None])

        if len(times) < threshold:
            continue

        left = 0
        for right in range(len(times)):
            while times[right] - times[left] > window_seconds:
                left += 1

            count_in_window = right - left + 1
            if count_in_window >= threshold:
                bursts.append({
                    "ip": ip,
                    "count": count_in_window,
                    "window_seconds": window_seconds
                })
                break

    return bursts


def analyze_logs(log_text):
    lines = [line.strip() for line in log_text.splitlines() if line.strip()]

    failed_count = 0
    success_count = 0
    failed_ips = Counter()
    failed_usernames = Counter()
    weird_hour_lines = []
    failed_attempts_by_ip = defaultdict(list)

    for line in lines:
        ip = extract_ip(line)
        hour = extract_hour(line)
        username = extract_username(line)
        seconds = extract_seconds_of_day(line)

        if is_failed_login(line):
            failed_count += 1

            if ip:
                failed_ips[ip] += 1
                failed_attempts_by_ip[ip].append({
                    "time": seconds,
                    "line": line
                })

            if username:
                failed_usernames[username] += 1

            if hour is not None and (hour <= 5 or hour >= 23):
                weird_hour_lines.append(line)

        elif is_success_login(line):
            success_count += 1

    repeated_failed_ips = {ip: count for ip, count in failed_ips.items() if count >= 3}
    suspicious_usernames = {
        username: count
        for username, count in failed_usernames.items()
        if username.lower() in COMMON_USERNAMES or count >= 3
    }

    bursts = detect_bursts(failed_attempts_by_ip, threshold=3, window_seconds=60)

    score = 0
    reasons = []

    if failed_count >= 5:
        score += 25
        reasons.append(f"High number of failed logins: {failed_count}")

    if repeated_failed_ips:
        score += 25
        reasons.append("One or more IPs have repeated failed login attempts")

    if suspicious_usernames:
        score += 20
        reasons.append("Common or repeatedly targeted usernames detected")

    if weird_hour_lines:
        score += 15
        reasons.append("Failed logins detected during unusual hours")

    if bursts:
        score += 25
        reasons.append("Burst behavior detected: many failed attempts in a short time")

    if failed_count > success_count and failed_count >= 3:
        score += 10
        reasons.append("Failed logins outweigh successful logins")

    score = min(score, 100)

    if score >= 60:
        risk = "High"
    elif score >= 30:
        risk = "Medium"
    else:
        risk = "Low"

    top_failed_ips = failed_ips.most_common(5)
    top_usernames = failed_usernames.most_common(5)

    summary = (
        f"Detected {failed_count} failed login attempts, "
        f"{len(repeated_failed_ips)} repeated IPs, and {len(bursts)} burst pattern(s)."
    )

    return {
        "total_lines": len(lines),
        "failed_count": failed_count,
        "success_count": success_count,
        "repeated_failed_ips": repeated_failed_ips,
        "suspicious_usernames": suspicious_usernames,
        "weird_hour_count": len(weird_hour_lines),
        "risk": risk,
        "score": score,
        "reasons": reasons if reasons else ["No major suspicious patterns found."],
        "bursts": bursts,
        "top_failed_ips": top_failed_ips,
        "top_usernames": top_usernames,
        "summary": summary
    }


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    log_text = ""

    if request.method == "POST":
        uploaded_file = request.files.get("log_file")
        log_text = request.form.get("log_text", "")

        if uploaded_file and uploaded_file.filename:
            file_bytes = uploaded_file.read()
            try:
                log_text = file_bytes.decode("utf-8")
            except UnicodeDecodeError:
                log_text = file_bytes.decode("latin-1")

        if log_text.strip():
            result = analyze_logs(log_text)

    return render_template("index.html", result=result, log_text=log_text)


if __name__ == "__main__":
    app.run(debug=True)