"""Writes data/sample.log: benign traffic plus the attack patterns from the simulator."""
from datetime import datetime, timedelta
t0 = datetime(2026, 8, 18, 10, 20, 0)
L = []
def add(s, ip, act, st, ua=""):
    L.append((t0 + timedelta(seconds=s), f"{ip} - {act} - {st}" + (f" - {ua}" if ua else "")))
for i in range(6): add(3 + i * 3, "192.168.1.45", "POST /login", 401)
add(24, "192.168.1.45", "POST /login", 200)
for i, p in enumerate([21, 22, 23, 25, 80, 443, 3306]): add(5 + i, "10.0.0.99", f"SYN port:{p}", "CLOSED")
add(7, "172.16.0.50", "GET /search?q=' OR 1=1--", 500)
add(10, "10.0.0.77", "GET /files/../../../etc/passwd", 400)
add(13, "192.168.1.100", "POST /login", 401, "curl/7.68")
add(14, "192.168.1.100", "POST /login", 401, "curl/7.68")
for i in range(8): add(i * 7, f"10.1.0.{i + 1}", "GET /index.html", 200)
add(30, "10.1.0.2", "POST /login", 401); add(60, "10.1.0.2", "POST /login", 200)
with open("data/sample.log", "w") as f:
    for ts, s in sorted(L): f.write(f"{s} - {ts.strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
