"""Stage 6: persistence. SQLite here; write a MongoDB class with the same methods to swap it in."""
import sqlite3

class Store:
    def __init__(self, path=":memory:"):
        self.c = sqlite3.connect(path, check_same_thread=False)
        self.c.row_factory = sqlite3.Row
        self.c.executescript("""
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ip TEXT, ts TEXT, kind TEXT, method TEXT,
            path TEXT, status TEXT, port INTEGER, ua TEXT, raw TEXT);
        CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, rule TEXT, ip TEXT, severity TEXT, ts TEXT,
            count INTEGER, detail TEXT);
        CREATE TABLE IF NOT EXISTS incidents(ip TEXT PRIMARY KEY, risk INTEGER, severity TEXT,
            status TEXT DEFAULT 'open', first_seen TEXT, last_seen TEXT, alert_count INTEGER, notes TEXT DEFAULT '');
        """)

    def add_events(self, events):
        self.c.executemany("INSERT INTO events(ip,ts,kind,method,path,status,port,ua,raw) VALUES "
                           "(:ip,:ts,:kind,:method,:path,:status,:port,:ua,:raw)", events)
        self.c.commit()

    def events(self, ip=None):
        if ip:
            rows = self.c.execute("SELECT * FROM events WHERE ip=? ORDER BY ts", (ip,))
        else:
            rows = self.c.execute("SELECT * FROM events ORDER BY ts")
        return [dict(r) for r in rows]

    def replace_alerts(self, alerts):
        self.c.execute("DELETE FROM alerts")
        self.c.executemany("INSERT INTO alerts(rule,ip,severity,ts,count,detail) VALUES "
                           "(:rule,:ip,:severity,:ts,:count,:detail)", alerts)
        self.c.commit()

    def upsert_incidents(self, incs):
        for i in incs:  # keeps analyst status/notes when re-scoring
            self.c.execute("""INSERT INTO incidents(ip,risk,severity,first_seen,last_seen,alert_count)
                VALUES(:ip,:risk,:severity,:first_seen,:last_seen,:alert_count)
                ON CONFLICT(ip) DO UPDATE SET risk=:risk, severity=:severity, first_seen=:first_seen,
                last_seen=:last_seen, alert_count=:alert_count""", i)
        self.c.commit()

    def incidents(self):
        return [dict(r) for r in self.c.execute("SELECT * FROM incidents ORDER BY risk DESC")]

    def incident(self, ip):
        r = self.c.execute("SELECT * FROM incidents WHERE ip=?", (ip,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["alerts"] = [dict(a) for a in self.c.execute("SELECT * FROM alerts WHERE ip=? ORDER BY ts", (ip,))]
        d["events"] = self.events(ip)
        return d

    def set_status(self, ip, status, notes=""):
        cur = self.c.execute("UPDATE incidents SET status=?, notes=? WHERE ip=?", (status, notes, ip))
        self.c.commit()
        return cur.rowcount > 0

    def summary(self):
        q = lambda s: self.c.execute(s).fetchone()[0]
        return {"events": q("SELECT COUNT(*) FROM events"), "alerts": q("SELECT COUNT(*) FROM alerts"),
                "incidents": q("SELECT COUNT(*) FROM incidents"),
                "open": q("SELECT COUNT(*) FROM incidents WHERE status!='resolved'"),
                "by_rule": {r[0]: r[1] for r in self.c.execute("SELECT rule,COUNT(*) FROM alerts GROUP BY rule")},
                "by_severity": {r[0]: r[1] for r in self.c.execute("SELECT severity,COUNT(*) FROM incidents GROUP BY severity")}}
