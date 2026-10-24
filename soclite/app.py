"""Stages 4, 10, 11: HTTP API + dashboard + investigation view (stdlib only)."""
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .storage import Store
from .pipeline import ingest

PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>SOC-Lite</title><style>
body{font:14px system-ui;margin:0;background:#0f172a;color:#e2e8f0}header{padding:14px 24px;background:#1e293b;font-size:18px;font-weight:600}
main{padding:20px 24px;max-width:1100px;margin:auto}.cards{display:flex;gap:12px;flex-wrap:wrap}
.card{background:#1e293b;padding:12px 18px;border-radius:8px;min-width:120px}.card b{display:block;font-size:26px}
table{width:100%;border-collapse:collapse;margin:12px 0;background:#1e293b}th,td{padding:8px;text-align:left;border-bottom:1px solid #334155}
tr.r{cursor:pointer}tr.r:hover{background:#334155}.critical{color:#f87171}.high{color:#fb923c}.medium{color:#facc15}.low{color:#4ade80}
textarea{width:100%;height:90px;background:#1e293b;color:#e2e8f0;border:1px solid #334155;border-radius:6px}
button,select{background:#3b82f6;color:#fff;border:0;padding:7px 14px;border-radius:6px;cursor:pointer}select{background:#334155}
#d{background:#1e293b;padding:14px;border-radius:8px;display:none}code{color:#93c5fd}</style>
<header>SOC-Lite &mdash; Security Monitoring</header><main>
<div class=cards id=s></div>
<h3>Ingest logs</h3><textarea id=t placeholder="Paste raw log lines..."></textarea><br><br>
<button onclick=ing()>Analyze</button> <span id=m></span>
<h3>Incidents (click to investigate)</h3><table id=i></table><div id=d></div></main>
<script>
const E=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function J(u,o){return (await fetch(u,o)).json()}
async function load(){const s=await J('/api/summary');
 s_.innerHTML=[['Events',s.events],['Alerts',s.alerts],['Incidents',s.incidents],['Open',s.open]].map(x=>`<div class=card>${x[0]}<b>${x[1]}</b></div>`).join('');
 const r=await J('/api/incidents');
 i_.innerHTML='<tr><th>IP<th>Risk<th>Severity<th>Alerts<th>Status</tr>'+r.map(x=>`<tr class=r onclick="show('${E(x.ip)}')"><td>${E(x.ip)}<td>${x.risk}<td class=${x.severity}>${x.severity}<td>${x.alert_count}<td>${E(x.status)}</tr>`).join('')}
async function show(ip){const x=await J('/api/incidents/'+ip);d_.style.display='block';
 d_.innerHTML=`<h3>Investigation: ${E(ip)} <span class=${x.severity}>(risk ${x.risk})</span></h3>
 <select id=st>${['open','investigating','resolved'].map(o=>`<option ${o==x.status?'selected':''}>${o}</option>`).join('')}</select>
 <button onclick="setS('${E(ip)}')">Update status</button>
 <h4>Alerts</h4><table>${x.alerts.map(a=>`<tr><td>${E(a.ts)}<td>${E(a.rule)}<td class=${a.severity}>${a.severity}<td>${E(a.detail)}</tr>`).join('')}</table>
 <h4>Event timeline</h4><table>${x.events.map(e=>`<tr><td>${E(e.ts)}<td><code>${E(e.raw)}</code></tr>`).join('')}</table>`}
async function setS(ip){await J('/api/incidents/'+ip+'/status',{method:'POST',body:JSON.stringify({status:st.value})});load();show(ip)}
async function ing(){const r=await J('/api/ingest',{method:'POST',body:t.value});m.textContent=`Parsed ${r.parsed}, bad lines ${r.bad_lines}, alerts ${r.alerts}`;load()}
const s_=document.getElementById('s'),i_=document.getElementById('i'),d_=document.getElementById('d'),t=document.getElementById('t'),m=document.getElementById('m');load();
</script>"""

def make_handler(store):
    class H(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else (body if ctype != "application/json" else json.dumps(body)).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def _body(self):
            n = min(int(self.headers.get("Content-Length") or 0), 5_000_000)  # cap request size
            return self.rfile.read(n).decode("utf-8", "replace")

        def do_GET(self):
            p = self.path.split("?")[0]
            if p == "/":
                return self._send(200, PAGE, "text/html; charset=utf-8")
            if p == "/api/summary":
                return self._send(200, store.summary())
            if p == "/api/incidents":
                return self._send(200, store.incidents())
            if p.startswith("/api/incidents/"):
                inc = store.incident(p.split("/")[3])
                return self._send(200 if inc else 404, inc or {"error": "not found"})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            p = self.path
            if p == "/api/ingest":
                return self._send(200, ingest(store, self._body()))
            if p.startswith("/api/incidents/") and p.endswith("/status"):
                try:
                    status = json.loads(self._body()).get("status")
                except ValueError:
                    status = None
                if status not in ("open", "investigating", "resolved"):
                    return self._send(400, {"error": "invalid status"})
                ok = store.set_status(p.split("/")[3], status)
                return self._send(200 if ok else 404, {"ok": ok})
            self._send(404, {"error": "not found"})

        def log_message(self, *a):
            pass
    return H

def main():
    store = Store("soclite.db")
    if len(sys.argv) > 1:
        print(ingest(store, open(sys.argv[1]).read()))
    print("SOC-Lite dashboard: http://127.0.0.1:8000")
    ThreadingHTTPServer(("127.0.0.1", 8000), make_handler(store)).serve_forever()

if __name__ == "__main__":
    main()
