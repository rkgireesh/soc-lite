import unittest, sys, os, json, threading, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from http.server import ThreadingHTTPServer
from soclite.parser import parse_line, parse_text
from soclite.detector import detect, score_ip, build_incidents
from soclite.storage import Store
from soclite.pipeline import ingest
from soclite.app import make_handler

SAMPLE = open(os.path.join(os.path.dirname(__file__), "..", "data", "sample.log")).read()
rules = lambda al, ip: {a["rule"] for a in al if a["ip"] == ip}

class T(unittest.TestCase):
    def test_parse_http_scan_ua_and_bad(self):
        self.assertEqual(parse_line("1.1.1.1 - POST /login - 401 - 2026-08-18T10:21:03Z")["path"], "/login")
        self.assertEqual(parse_line("1.1.1.1 - SYN port:22 - CLOSED - 2026-08-18T10:21:03Z")["port"], 22)
        self.assertEqual(parse_line("1.1.1.1 - POST /login - 401 - curl/7.68 - 2026-08-18T10:21:03Z")["ua"], "curl/7.68")
        self.assertIsNone(parse_line("garbage"))
        self.assertIsNone(parse_line("1.1.1.1 - GET /x - 200 - not-a-date"))
        self.assertEqual(parse_text("garbage\n\n")[1], 1)

    def test_detections_on_sample(self):
        al = detect(parse_text(SAMPLE)[0])
        self.assertEqual(rules(al, "192.168.1.45"), {"brute_force", "brute_force_success"})
        self.assertEqual(rules(al, "10.0.0.99"), {"port_scan"})
        self.assertEqual(rules(al, "172.16.0.50"), {"sql_injection"})
        self.assertEqual(rules(al, "10.0.0.77"), {"path_traversal"})

    def test_no_false_positives(self):
        al = detect(parse_text(SAMPLE)[0])
        self.assertEqual(rules(al, "10.1.0.2"), set())      # one failed login then success
        self.assertEqual(rules(al, "192.168.1.100"), set())  # only 2 failures, curl is not on the bad-UA list

    def test_brute_force_needs_window(self):
        lines = "\n".join(f"9.9.9.9 - POST /login - 401 - 2026-08-18T10:{m:02d}:00Z" for m in range(10))
        self.assertEqual(detect(parse_text(lines)[0]), [])

    def test_scoring_correlation_and_cap(self):
        al = detect(parse_text(SAMPLE)[0])
        mine = [a for a in al if a["ip"] == "192.168.1.45"]
        self.assertEqual(score_ip(mine), 95)  # 30 + 50 + 15 correlation bonus
        inc = build_incidents(al)
        self.assertEqual(inc[0]["ip"], "192.168.1.45")
        self.assertTrue(all(0 <= i["risk"] <= 100 for i in inc))

    def test_pipeline_keeps_status(self):
        s = Store()
        r = ingest(s, SAMPLE)
        self.assertEqual((r["parsed"], r["bad_lines"]), (28, 0))
        s.set_status("10.0.0.99", "resolved")
        ingest(s, "")
        self.assertEqual(s.incident("10.0.0.99")["status"], "resolved")

    def test_http_api(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(Store()))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_port}"
        req = lambda p, d=None: json.load(urllib.request.urlopen(urllib.request.Request(base + p, data=d)))
        self.assertEqual(req("/api/ingest", SAMPLE.encode())["alerts"], 5)
        self.assertEqual(req("/api/summary")["incidents"], 4)
        self.assertEqual(len(req("/api/incidents/192.168.1.45")["alerts"]), 2)
        self.assertIn(b"SOC-Lite", urllib.request.urlopen(base + "/").read())
        with self.assertRaises(urllib.error.HTTPError):
            req("/api/incidents/1.2.3.4/status", b'{"status":"bogus"}')
        srv.shutdown()

if __name__ == "__main__":
    unittest.main()
