# SOC-Lite: Log Analyzer & Threat Detection Platform

Ingests raw security logs, parses and normalizes them, detects threats with rules, scores risk,
groups alerts into incidents, and shows everything on a dashboard with an investigation view.
Pure Python 3 standard library (no installs). Storage is SQLite behind `soclite/storage.py`.

## Run
    python3 generate_logs.py            # creates data/sample.log
    python3 -m soclite.app data/sample.log   # ingest sample, serve http://127.0.0.1:8000
    python3 -m unittest discover -s tests -v

## Pipeline
`parser.py` (raw line -> event) -> `storage.py` -> `detector.py` (rules) -> risk score -> incident per source IP.

| Rule | Trigger | Severity |
|---|---|---|
| brute_force | >=5 failed `/login` in 60s from one IP | high |
| brute_force_success | successful login after the above | critical |
| port_scan | >=5 distinct ports probed in 60s | medium |
| sql_injection / path_traversal | pattern in request path | high |
| scanner_user_agent | sqlmap, nikto, nmap, hydra | low |

Risk = sum of severity weights (low 5, medium 15, high 30, critical 50), +15 when 2+ different rules fire
for the same IP (correlation), capped at 100. Levels: <30 low, 30-59 medium, 60-79 high, 80+ critical.

## API
`POST /api/ingest` (raw text) | `GET /api/summary` | `GET /api/incidents` | `GET /api/incidents/<ip>` |
`POST /api/incidents/<ip>/status` `{"status": "open|investigating|resolved"}`

## Security notes
Parameterized SQL only, dashboard escapes all log content (logs are attacker-controlled), request size cap,
binds to 127.0.0.1, no auth (add it before exposing publicly).

## Limitations / next steps
Rules are threshold-based and per-IP (no distributed attacks); detection re-scans all events on each ingest;
add a MongoDB `Store`, auth, and a log-tail agent.

## Push to GitHub
    git init && git add . && git commit -m "SOC-Lite: log analyzer and threat detection"
    git branch -M main && git remote add origin <your-repo-url> && git push -u origin main

## Deploy
Any VM/Render/Railway: `python3 -m soclite.app` (change host to 0.0.0.0 and put it behind HTTPS + auth).
