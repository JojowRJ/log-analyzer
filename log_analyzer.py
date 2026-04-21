import re
import requests
from collections import defaultdict
from datetime import datetime

# === SEUILS DE DETECTION ===
BRUTE_FORCE_THRESHOLD = 5
RECON_THRESHOLD = 4
SQLI_PATTERNS = ["union select", "or '1'='1", "drop table", "admin'--", "1=1"]
XSS_PATTERNS = ["<script>", "onerror=", "alert("]
TRAVERSAL_PATTERNS = ["../", "..%2f", "etc/passwd", "windows/system32"]
SCANNER_UAS = ["nikto", "sqlmap", "nmap", "masscan", "zgrab"]

def parse_logs(filename):
    logs = []
    pattern = r'(\d+\.\d+\.\d+\.\d+).*\[(.+)\] "(\w+) (\S+) HTTP.*" (\d+) (\d+)(.*)'
    with open(filename, "r") as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                ua = match.group(7).strip().strip('"')
                logs.append({
                    "ip": match.group(1),
                    "date": match.group(2),
                    "method": match.group(3),
                    "path": match.group(4).lower(),
                    "status": int(match.group(5)),
                    "ua": ua.lower()
                })
    return logs

def detect_brute_force(logs):
    failed = defaultdict(int)
    for log in logs:
        if "/login" in log["path"] and log["status"] == 401:
            failed[log["ip"]] += 1
    return [{"type": "BRUTE FORCE", "ip": ip, "score": min(count * 10, 100),
             "detail": f"{count} tentatives de login echouees"}
            for ip, count in failed.items() if count >= BRUTE_FORCE_THRESHOLD]

def detect_recon(logs):
    errors = defaultdict(list)
    for log in logs:
        if log["status"] == 404:
            errors[log["ip"]].append(log["path"])
    return [{"type": "RECONNAISSANCE", "ip": ip, "score": min(len(paths) * 8, 100),
             "detail": f"{len(paths)} pages introuvables : {', '.join(set(paths))[:80]}"}
            for ip, paths in errors.items() if len(paths) >= RECON_THRESHOLD]

def detect_sqli(logs):
    hits = defaultdict(int)
    for log in logs:
        if any(p in log["path"] for p in SQLI_PATTERNS):
            hits[log["ip"]] += 1
    return [{"type": "INJECTION SQL", "ip": ip, "score": 90,
             "detail": f"{count} tentatives d'injection SQL detectees"}
            for ip, count in hits.items() if count > 0]

def detect_xss(logs):
    hits = defaultdict(int)
    for log in logs:
        if any(p in log["path"] for p in XSS_PATTERNS):
            hits[log["ip"]] += 1
    return [{"type": "XSS", "ip": ip, "score": 80,
             "detail": f"{count} tentatives XSS detectees"}
            for ip, count in hits.items() if count > 0]

def detect_traversal(logs):
    hits = defaultdict(int)
    for log in logs:
        if any(p in log["path"] for p in TRAVERSAL_PATTERNS):
            hits[log["ip"]] += 1
    return [{"type": "DIRECTORY TRAVERSAL", "ip": ip, "score": 95,
             "detail": f"{count} tentatives de traversee de repertoire"}
            for ip, count in hits.items() if count > 0]

def detect_scanners(logs):
    hits = defaultdict(set)
    for log in logs:
        for scanner in SCANNER_UAS:
            if scanner in log["ua"]:
                hits[log["ip"]].add(scanner)
    return [{"type": "SCANNER AUTOMATIQUE", "ip": ip, "score": 85,
             "detail": f"Scanner detecte : {', '.join(scanners)}"}
            for ip, scanners in hits.items()]

def geolocate(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        d = r.json()
        return f"{d.get('country','?')}, {d.get('city','?')} ({d.get('isp','?')})"
    except:
        return "Geolocalisation indisponible"

def generate_html(logs, all_alerts):
    date = datetime.now().strftime("%d/%m/%Y %H:%M")
    ip_scores = defaultdict(int)
    for alert in all_alerts:
        ip_scores[alert["ip"]] = max(ip_scores[alert["ip"]], alert["score"])

    rows = ""
    for alert in all_alerts:
        score = alert["score"]
        if score >= 80:
            color = "#ff4444"
        elif score >= 50:
            color = "#ff8800"
        else:
            color = "#ffcc00"
        geo = geolocate(alert["ip"])
        rows += (
            "<tr>"
            f"<td style='color:{color};font-weight:bold'>{alert['type']}</td>"
            f"<td>{alert['ip']}</td>"
            f"<td style='color:{color};font-weight:bold'>{score}/100</td>"
            f"<td>{alert['detail']}</td>"
            f"<td>{geo}</td>"
            "</tr>"
        )

    html = (
        "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
        "<title>Log Analyzer</title>"
        "<style>"
        "body{font-family:Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:30px;}"
        "h1{color:#58a6ff;}"
        ".stats{display:flex;gap:20px;margin:20px 0;}"
        ".stat{background:#161b22;padding:15px 25px;border-radius:8px;text-align:center;}"
        ".num{font-size:32px;font-weight:bold;color:#58a6ff;}"
        ".danger .num{color:#ff4444;}"
        "table{width:100%;border-collapse:collapse;margin-top:20px;}"
        "th{background:#161b22;padding:10px;text-align:left;}"
        "td{padding:10px;border-bottom:1px solid #21262d;vertical-align:top;}"
        "tr:hover{background:#161b22;}"
        "</style></head><body>"
        f"<h1>Log Analyzer — Rapport du {date}</h1>"
        "<div class='stats'>"
        f"<div class='stat'><div class='num'>{len(logs)}</div>Lignes analysees</div>"
        f"<div class='stat danger'><div class='num'>{len(all_alerts)}</div>Alertes</div>"
        f"<div class='stat danger'><div class='num'>{len(set(a['ip'] for a in all_alerts))}</div>IPs suspectes</div>"
        "</div>"
        "<table><tr><th>Type</th><th>IP</th><th>Score</th><th>Detail</th><th>Localisation</th></tr>"
        + rows +
        "</table></body></html>"
    )
    with open("security_report.html", "w", encoding="utf-8") as f:
        f.write(html)
    print("[+] Rapport genere : security_report.html")

# === MAIN ===
print("=" * 60)
print("     LOG ANALYZER — Detection d'Intrusion")
print("=" * 60)

logs = parse_logs("access.log")
print(f"\n[*] {len(logs)} lignes analysees\n")

all_alerts = []
all_alerts += detect_brute_force(logs)
all_alerts += detect_recon(logs)
all_alerts += detect_sqli(logs)
all_alerts += detect_xss(logs)
all_alerts += detect_traversal(logs)
all_alerts += detect_scanners(logs)

print(f"[!] {len(all_alerts)} alertes detectees\n")
for a in all_alerts:
    print(f"[{a['score']:3}/100] {a['type']:<25} | {a['ip']:<15} | {a['detail'][:60]}")

print("\n[*] Geolocalisation et generation du rapport HTML...")
generate_html(logs, all_alerts)
print("\n" + "=" * 60)