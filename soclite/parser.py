"""Stage 5: parse raw log lines into normalized event dicts."""
from datetime import datetime

TS_FMT = "%Y-%m-%dT%H:%M:%SZ"

def parse_line(line):
    """Return a normalized event dict, or None if the line is malformed."""
    line = line.strip()
    parts = line.split(" - ")
    if len(parts) not in (4, 5):
        return None
    ip, action, status, ts = parts[0], parts[1], parts[2], parts[-1]
    ua = parts[3] if len(parts) == 5 else ""
    try:
        datetime.strptime(ts, TS_FMT)
    except ValueError:
        return None
    ev = {"ip": ip, "ts": ts, "status": status, "ua": ua, "raw": line,
          "kind": "http", "method": "", "path": "", "port": None}
    if action.startswith("SYN port:"):
        try:
            ev.update(kind="scan", port=int(action[9:]))
        except ValueError:
            return None
    else:
        method, _, path = action.partition(" ")
        if not path:
            return None
        ev.update(method=method, path=path)
    return ev

def parse_text(text):
    """Parse many lines; returns (events, number_of_bad_lines)."""
    events, bad = [], 0
    for line in text.splitlines():
        if not line.strip():
            continue
        ev = parse_line(line)
        if ev:
            events.append(ev)
        else:
            bad += 1
    return events, bad
