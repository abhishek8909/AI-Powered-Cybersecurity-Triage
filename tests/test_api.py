"""End-to-end HTTP API integration tests for PS06 Cybersecurity Triage server."""

from __future__ import annotations

import http.client
import json
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

from src.sample_data import SAMPLE_ALERTS
from src.security import MAX_BODY_BYTES
from src.server import TriageHTTPServer


class TestTriageAPI(unittest.TestCase):
    server: TriageHTTPServer
    thread: threading.Thread
    port: int
    base_url: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = TriageHTTPServer(("127.0.0.1", 0), rate_limit_per_min=200, api_token="")
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def _request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        req_headers = dict(headers) if headers is not None else {}
        if body is not None and "Content-Type" not in req_headers:
            req_headers["Content-Type"] = "application/json"
        req = urllib.request.Request(f"{self.base_url}{path}", data=body, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status, dict(resp.headers.items()), resp.read()
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers.items()), err.read()

    def test_health_and_head_headers(self) -> None:
        status, headers, raw = self._request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["status"], "ok")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(headers.get("Cross-Origin-Opener-Policy"), "same-origin")
        self.assertEqual(headers.get("Cross-Origin-Resource-Policy"), "same-origin")
        self.assertIn("default-src 'self'", headers.get("Content-Security-Policy", ""))

        head_status, head_headers, _ = self._request("HEAD", "/")
        self.assertEqual(head_status, 200)
        self.assertIn("text/html", head_headers.get("Content-Type", ""))

    def test_sample_alerts_and_batch_triage_roundtrip(self) -> None:
        status, _, raw = self._request("GET", "/api/sample-alerts")
        self.assertEqual(status, 200)
        alerts = json.loads(raw)["alerts"]
        self.assertEqual(len(alerts), len(SAMPLE_ALERTS))

        payload = json.dumps({"alerts": alerts}).encode("utf-8")
        status, _, triage_raw = self._request("POST", "/api/triage/batch", payload)
        self.assertEqual(status, 200)
        body = json.loads(triage_raw)
        self.assertEqual(body["total_alerts_ingested"], 8)
        self.assertEqual(body["unique_incidents"], 6)
        self.assertEqual(body["incidents"][0]["decision"], "CONTAIN_PENDING_APPROVAL")
        self.assertEqual(len(body["incidents"][0]["agent_trace"]), 6)

    def test_single_triage_endpoint(self) -> None:
        payload = json.dumps({
            "title": "Ransomware Mass Encryption Detected",
            "description": "vssadmin shadow copy delete observed",
            "dest_host": "dc-primary-01",
            "raw_severity": "critical",
        }).encode("utf-8")
        status, _, raw = self._request("POST", "/api/triage", payload)
        self.assertEqual(status, 200)
        body = json.loads(raw)
        ids = {m["technique_id"] for m in body["incidents"][0]["mitre"]}
        self.assertIn("T1486", ids)
        self.assertIn("T1490", ids)

    def test_http_error_statuses_400_404_411_413_415_500(self) -> None:
        # 404 path traversal
        status, _, _ = self._request("GET", "/../src/server.py")
        self.assertEqual(status, 404)

        # 415 wrong Content-Type
        status, _, _ = self._request("POST", "/api/triage", b"{}", headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 415)

        # 411 missing Content-Length via raw HTTP connection
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.putrequest("POST", "/api/triage")
        conn.putheader("Content-Type", "application/json")
        conn.endheaders()
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 411)

        # 413 payload too large
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.putrequest("POST", "/api/triage")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(MAX_BODY_BYTES + 10))
        conn.endheaders()
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 413)

        # 400 malformed JSON
        status, _, raw = self._request("POST", "/api/triage/batch", b"{not-json")
        self.assertEqual(status, 400)
        self.assertIn("Malformed JSON", json.loads(raw)["error"])

        # 500 generic error (no stack trace leaked)
        with patch("src.server.triage_batch", side_effect=RuntimeError("sensitive db password")):
            status, _, raw = self._request("POST", "/api/triage", json.dumps({"title": "x"}).encode("utf-8"))
        self.assertEqual(status, 500)
        self.assertNotIn(b"sensitive db password", raw)

    def test_bearer_auth_and_rate_limit_429_with_retry_after(self) -> None:
        auth_srv = TriageHTTPServer(("127.0.0.1", 0), rate_limit_per_min=2, api_token="top-secret")
        auth_port = auth_srv.server_address[1]
        auth_thread = threading.Thread(target=auth_srv.serve_forever, daemon=True)
        auth_thread.start()
        try:
            url = f"http://127.0.0.1:{auth_port}/api/triage"
            body = json.dumps({"title": "Test alert"}).encode("utf-8")

            # Missing token -> 401
            req1 = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
            with self.assertRaises(urllib.error.HTTPError) as ctx1:
                urllib.request.urlopen(req1, timeout=3)
            self.assertEqual(ctx1.exception.code, 401)

            # Valid token -> 200
            req2 = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": "application/json", "Authorization": "Bearer top-secret"},
                method="POST",
            )
            with urllib.request.urlopen(req2, timeout=3) as r2:
                self.assertEqual(r2.status, 200)

            # Third request hits rate_limit_per_min=2 -> 429 + Retry-After
            req3 = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": "application/json", "Authorization": "Bearer top-secret"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx3:
                urllib.request.urlopen(req3, timeout=3)
            self.assertEqual(ctx3.exception.code, 429)
            self.assertTrue(ctx3.exception.headers.get("Retry-After"))
        finally:
            auth_srv.shutdown()
            auth_srv.server_close()
            auth_thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
