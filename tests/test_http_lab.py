"""HTTP testing lab: repeater, intruder, spider, match rules, proxy."""

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.execution import http_lab as L


class _EchoHandler(BaseHTTPRequestHandler):
    """Minimal lab target: echoes method/URL/body and a flag endpoint."""

    def _reply(self, code=200, extra=""):
        body = f"method={self.command} path={self.path} {extra}".encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/admin":
            self._reply(403)
        else:
            self._reply()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        self._reply(extra=f"body={body}")

    def log_message(self, *args):
        pass


@pytest.fixture()
def target():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_repeater_gets_response(target):
    result = L.repeater({"method": "GET", "url": f"{target}/home"})
    assert result["ok"] is True
    assert result["status"] == 200
    assert "/home" in result["body"]
    assert result["duration_s"] >= 0


def test_repeater_sees_status_codes(target):
    result = L.repeater({"method": "GET", "url": f"{target}/admin"})
    assert result["status"] == 403
    assert result["ok"] is False


def test_repeater_posts_body(target):
    result = L.repeater({
        "method": "POST", "url": f"{target}/login",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body": "user=admin&pass=x",
    })
    assert "user=admin&pass=x" in result["body"]


def test_intruder_sniper(target):
    result = L.intruder(
        {"method": "GET", "url": f"{target}/user?id=§id§", "body": ""},
        ["1", "2", "3"],
        workers=3,
    )
    assert result["ok"] is True
    assert result["total"] == 3
    assert result["distinct_statuses"] == [200]


def test_intruder_requires_payloads(target):
    result = L.intruder({"method": "GET", "url": target}, [])
    assert result["ok"] is False


def test_spider_same_origin_and_statuses(target):
    result = L.spider(target, max_pages=10)
    assert result["ok"] is True
    assert result["pages_crawled"] >= 1
    assert all(p["url"].startswith(target) for p in result["pages"])
    assert 200 in {p["status"] for p in result["pages"]}


def test_spider_requires_scheme():
    assert L.spider("example.com").get("ok") is False


def test_match_rules_regex():
    rules = [{"match": r"user=admin", "replace": "user=guest"},
             {"match": r"\d{4}", "replace": "XXXX"}]
    out = L.apply_match_rules(rules, "user=admin&pin=1234")
    assert out == "user=guest&pin=XXXX"
    with pytest.raises(ValueError):
        L.apply_match_rules([{"match": "([", "replace": ""}], "x")


def test_proxy_forwards_and_logs(target):
    import urllib.request

    proxy = L.LabProxy(port=0)
    assert proxy.start()["ok"] is True
    actual_port = proxy._server.server_address[1]
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{actual_port}"})
    )
    req = urllib.request.Request(f"{target}/echo", method="POST", data=b"foo=1")
    resp = opener.open(req, timeout=5)
    assert resp.status == 200
    assert "body=foo=1" in resp.read().decode()
    logs = proxy.request_logs()
    assert len(logs) >= 1
    assert logs[-1]["method"] == "POST"
    assert proxy.stop()["ok"] is True
