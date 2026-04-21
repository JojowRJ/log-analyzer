import random
from datetime import datetime, timedelta

# IPs simulées
NORMAL_IPS = ["172.16.0.5", "172.16.0.8", "192.168.1.10", "192.168.1.15"]
BRUTE_FORCE_IP = "77.88.8.8"        # Russie
RECON_IP = "223.5.5.5"              # Chine
SQLI_IP = "5.2.78.226"              # Roumanie
SCANNER_IP = "185.220.101.34"       # Pays-Bas

NORMAL_PAGES = ["/", "/index.html", "/about", "/contact", "/products", "/login"]
HIDDEN_PAGES = ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config", "/backup", "/.git", "/api/keys"]
SQLI_PAYLOADS = [
    "/login?id=1' OR '1'='1",
    "/search?q=1 UNION SELECT * FROM users--",
    "/user?id=1; DROP TABLE users--",
    "/login?user=admin'--",
]
XSS_PAYLOADS = [
    "/search?q=<script>alert(1)</script>",
    "/comment?text=<img src=x onerror=alert(1)>",
]
TRAVERSAL_PAYLOADS = [
    "/../../../etc/passwd",
    "/..%2F..%2F..%2Fetc%2Fshadow",
    "/../windows/system32/cmd.exe",
]
SCANNERS = ["Nikto/2.1.6", "sqlmap/1.7", "nmap scripting engine", "masscan/1.0"]

def random_date(start, end):
    delta = end - start
    return start + timedelta(seconds=random.randint(0, int(delta.total_seconds())))

def format_log(ip, date, method, path, status, size, ua="Mozilla/5.0"):
    return f'{ip} - - [{date.strftime("%d/%Apr/%Y:%H:%M:%S")}] "{method} {path} HTTP/1.1" {status} {size} "{ua}"\n'

start = datetime(2026, 4, 20, 6, 0, 0)
end = datetime(2026, 4, 20, 23, 59, 59)
lines = []

# Trafic normal
for _ in range(200):
    ip = random.choice(NORMAL_IPS)
    path = random.choice(NORMAL_PAGES)
    date = random_date(start, end)
    lines.append((date, format_log(ip, date, "GET", path, 200, random.randint(512, 4096))))

# Brute force
for i in range(50):
    date = datetime(2026, 4, 20, 8, 0, 0) + timedelta(seconds=i*2)
    status = 401 if i < 48 else 200
    lines.append((date, format_log(BRUTE_FORCE_IP, date, "POST", "/login", status, 512)))

# Reconnaissance
for page in HIDDEN_PAGES * 2:
    date = random_date(datetime(2026, 4, 20, 10, 0, 0), datetime(2026, 4, 20, 10, 30, 0))
    lines.append((date, format_log(RECON_IP, date, "GET", page, 404, 256)))

# Injections SQL
for payload in SQLI_PAYLOADS * 3:
    date = random_date(datetime(2026, 4, 20, 14, 0, 0), datetime(2026, 4, 20, 14, 30, 0))
    lines.append((date, format_log(SQLI_IP, date, "GET", payload, 403, 128)))

# XSS
for payload in XSS_PAYLOADS * 3:
    date = random_date(datetime(2026, 4, 20, 15, 0, 0), datetime(2026, 4, 20, 15, 30, 0))
    lines.append((date, format_log(SQLI_IP, date, "GET", payload, 403, 128)))

# Directory traversal
for payload in TRAVERSAL_PAYLOADS * 2:
    date = random_date(datetime(2026, 4, 20, 16, 0, 0), datetime(2026, 4, 20, 16, 30, 0))
    lines.append((date, format_log(SQLI_IP, date, "GET", payload, 403, 128)))

# Scanner automatique
for _ in range(30):
    date = random_date(datetime(2026, 4, 20, 20, 0, 0), datetime(2026, 4, 20, 21, 0, 0))
    path = random.choice(HIDDEN_PAGES + NORMAL_PAGES)
    ua = random.choice(SCANNERS)
    lines.append((date, format_log(SCANNER_IP, date, "GET", path, random.choice([200, 404, 403]), 256, ua)))

# Trier par date et écrire
lines.sort(key=lambda x: x[0])
with open("access.log", "w") as f:
    for _, line in lines:
        f.write(line)

print(f"[+] {len(lines)} lignes de logs générées dans access.log")