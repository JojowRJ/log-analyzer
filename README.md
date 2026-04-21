# Log Analyzer 🛡️

Mini-SIEM Python — analyse de logs Apache et détection d'intrusion multi-vecteurs.

## Détections

| Type | Description | Score |
|------|-------------|-------|
| Brute Force | Tentatives de login répétées | 0-100 |
| Reconnaissance | Scan de pages cachées (404 en masse) | 0-100 |
| Injection SQL | Payloads SQLi dans les URLs | 90/100 |
| XSS | Tentatives Cross-Site Scripting | 80/100 |
| Directory Traversal | Accès aux fichiers système | 95/100 |
| Scanner automatique | Nikto, sqlmap, Nmap, masscan | 85/100 |

## Fonctionnement

```bash
# 1. Générer des logs réalistes
python generate_logs.py

# 2. Analyser et détecter les menaces
python log_analyzer.py

# 3. Ouvrir le rapport HTML
start security_report.html
