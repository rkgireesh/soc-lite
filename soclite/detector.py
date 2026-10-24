"""Stage 7-9: rule-based detection, risk scoring, incident building."""
import re
from collections import defaultdict
from datetime import datetime
from .parser import TS_FMT

WINDOW = 60          # seconds
FAIL_THRESHOLD = 5   # failed logins in window
SCAN_THRESHOLD = 5   # distinct ports in window
SQLI = re.compile(r"('|%27)\s*(or|and)\s+\S+=|union\s+select|--|;\s*drop\s", re.I)
TRAVERSAL = re.compile(r"\.\./|%2e%2e%2f", re.I)
BAD_UA = re.compile(r"sqlmap|nikto|nmap|hydra", re.I)
WEIGHT = {"low": 5, "medium": 15, "high": 30, "critical": 50}

def _t(ts):
    return datetime.strptime(ts, TS_FMT)

def _alert(rule, ip, sev, ts, count, detail):
    return {"rule": rule, "ip": ip, "severity": sev, "ts": ts, "count": count, "detail": detail}

def detect(events):
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)
    alerts = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e["ts"])
        # Brute force: many failed logins in a short window, then success
        fails = [e for e in evs if e["path"].startswith("/login") and e["status"] in ("401", "403")]
        for i in range(len(fails) - FAIL_THRESHOLD + 1):
            first, last = fails[i], fails[i + FAIL_THRESHOLD - 1]
            if (_t(last["ts"]) - _t(first["ts"])).total_seconds() <= WINDOW:
                alerts.append(_alert("brute_force", ip, "high", first["ts"], len(fails),
                                     f"{len(fails)} failed logins within {WINDOW}s"))
                win = [e for e in evs if e["path"].startswith("/login") and e["status"] == "200"
                       and e["ts"] >= first["ts"]]
                if win:
                    alerts.append(_alert("brute_force_success", ip, "critical", win[0]["ts"], 1,
                                         "Successful login after repeated failures: possible account takeover"))
                break
        # Port scan: many distinct ports probed in a short window
        syns = [e for e in evs if e["kind"] == "scan"]
        for i in range(len(syns)):
            ports = {s["port"] for s in syns[i:] if (_t(s["ts"]) - _t(syns[i]["ts"])).total_seconds() <= WINDOW}
            if len(ports) >= SCAN_THRESHOLD:
                alerts.append(_alert("port_scan", ip, "medium", syns[i]["ts"], len(ports),
                                     f"{len(ports)} distinct ports probed within {WINDOW}s"))
                break
        # Single-event rules
        for rule, rx, msg in (("sql_injection", SQLI, "SQL injection pattern in request"),
                              ("path_traversal", TRAVERSAL, "Directory traversal attempt")):
            hits = [e for e in evs if e["kind"] == "http" and rx.search(e["path"])]
            if hits:
                alerts.append(_alert(rule, ip, "high", hits[0]["ts"], len(hits), f"{msg}: {hits[0]['path']}"))
        tool = [e for e in evs if e["ua"] and BAD_UA.search(e["ua"])]
        if tool:
            alerts.append(_alert("scanner_user_agent", ip, "low", tool[0]["ts"], len(tool),
                                 f"Known attack tool user-agent: {tool[0]['ua']}"))
    return sorted(alerts, key=lambda a: (a["ts"], a["ip"]))

def risk_level(score):
    return "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low"

def score_ip(alerts):
    """Risk 0-100: sum of severity weights, +15 when multiple distinct rules fire (correlation)."""
    score = sum(WEIGHT[a["severity"]] for a in alerts)
    if len({a["rule"] for a in alerts}) >= 2:
        score += 15
    return min(100, score)

def build_incidents(alerts):
    """One incident per source IP, with a risk score."""
    grouped = defaultdict(list)
    for a in alerts:
        grouped[a["ip"]].append(a)
    out = []
    for ip, al in grouped.items():
        s = score_ip(al)
        out.append({"ip": ip, "risk": s, "severity": risk_level(s), "first_seen": min(a["ts"] for a in al),
                    "last_seen": max(a["ts"] for a in al), "alert_count": len(al)})
    return sorted(out, key=lambda i: -i["risk"])
