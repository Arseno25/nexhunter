"""HTTP testing lab: repeat, intrude, spider, match-and-replace.

A stdlib-only analogue of a manual web testing kit, for lab use against
authorized targets. Every operation is a plain HTTP client call -- nothing
here proxies your own traffic outside the lab nor installs anything.

  * repeater   - fire one hand-tuned request, get the full response
  * intruder   - replace ``§position§`` markers in a template with payloads
                 (sniper), each substitution fired and classified
  * spider     - walk links from a seed URL, same-origin only
  * match_rules- string/regex replacements applied to requests before they
                 go out (the primitive the proxy uses)
  * lab_proxy  - tiny forward proxy that logs requests and applies
                 match-replace rules; for local lab testing only

Output is always capped; bodies are truncated at MAX_BODY bytes.
"""

from __future__ import annotations

import html.parser
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any

MAX_BODY = 200_000  # chars kept from a response body
MAX_LINES = 4_000
PROXY_MAX_BODY = 500_000
SPIDER_MAX_PAGES = 200
DEFAULT_TIMEOUT = 15


class HttpRequest:
    """One hand-built request: method, url, headers, body."""

    def __init__(self, method: str = "GET", url: str = "",
                 headers: dict[str, str] | None = None,
                 body: str = ""):
        self.method = method.upper()
        self.url = url
        self.headers = {k: v for k, v in (headers or {}).items()}
        self.body = body

    def to_dict(self) -> dict:
        return {
            "method": self.method, "url": self.url,
            "headers": self.headers, "body": self.body,
        }

    @classmethod
    def from_dict(cls, data: dict) -> HttpRequest:
        return cls(
            method=data.get("method", "GET"),
            url=data.get("url", ""),
            headers=data.get("headers") or {},
            body=data.get("body", ""),
        )


class HttpResponse:
    """A measured response: status, headers, body slice, timing."""

    def __init__(self, status: int, headers: dict, body: str,
                 duration_s: float, error: str = ""):
        self.status = status
        self.headers = headers
        self.body = body
        self.duration_s = duration_s
        self.error = error

    def to_dict(self, include_body: bool = True) -> dict:
        return {
            "status": self.status,
            "headers": self.headers,
            "body": self.body[:MAX_BODY] if include_body else "",
            "body_chars": len(self.body),
            "duration_s": round(self.duration_s, 3),
            "error": self.error,
        }

    @property
    def ok(self) -> bool:
        return not self.error and 200 <= self.status < 400


def apply_match_rules(rules: list[dict], text: str) -> str:
    """Apply [{match, replace}] rules, match being a regex."""
    for rule in rules or []:
        try:
            pattern = rule.get("match", "")
            if not pattern:
                continue
            text = re.sub(pattern, rule.get("replace", ""), text)
        except re.error as exc:
            raise ValueError(f"bad match rule '{pattern}': {exc}") from exc
    return text


def _send(method: str, url: str, headers: dict, body: str,
          timeout: int, follow_redirects: bool = False) -> HttpResponse:
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"refusing non-http URL: {url}")
    req = urllib.request.Request(url, method=method, headers=headers)  # noqa: S310 - scheme guard above
    data = None
    if method in ("POST", "PUT", "PATCH"):
        data = body.encode() if body else None
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(  # nosec B310 - scheme guard above
            req, data=data, timeout=timeout,
        ) as resp:
            duration = time.monotonic() - t0
            raw = resp.read(MAX_BODY + 1)
            text = raw[:MAX_BODY].decode("utf-8", errors="replace")
            return HttpResponse(
                status=resp.status,
                headers=dict(resp.headers.items()),
                body=text,
                duration_s=duration,
            )
    except urllib.error.HTTPError as exc:
        duration = time.monotonic() - t0
        text = (exc.read(MAX_BODY + 1)[:MAX_BODY]
                .decode("utf-8", errors="replace"))
        return HttpResponse(
            status=exc.code, headers=dict(exc.headers.items()),
            body=text, duration_s=duration,
        )
    except (urllib.error.URLError, OSError, ValueError) as exc:
        duration = time.monotonic() - t0
        return HttpResponse(
            status=0, headers={}, body="", duration_s=duration,
            error=str(exc),
        )


def repeater(request: dict, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Send one request exactly as specified; return the full response."""
    req = HttpRequest.from_dict(request)
    if not req.url:
        return {"ok": False, "error": "url is required"}
    resp = _send(req.method, req.url, req.headers, req.body,
                 timeout=timeout)
    out = resp.to_dict()
    out["request"] = req.to_dict()
    out["ok"] = resp.ok
    return out


def intruder(request: dict, payloads: list[str],
             timeout: int = DEFAULT_TIMEOUT, workers: int = 5,
             follow_redirects: bool = False) -> dict:
    """Sniper-style fuzzing: replace each ``§marker§`` in the template with
    each payload, fire every variant, classify the responses.

    Payload length and count are capped for lab sanity.
    """
    req = HttpRequest.from_dict(request)
    if not req.url:
        return {"ok": False, "error": "url is required"}
    if not isinstance(payloads, list) or not payloads:
        return {"ok": False, "error": "payloads must be a non-empty list"}
    payloads = [str(p)[:2_000] for p in payloads[:2_000]]

    template_body = req.body

    def build_url(payload: str) -> str:
        return re.sub(r"§[^§]*§", payload, req.url)

    def build_body(payload: str) -> str:
        return re.sub(r"§[^§]*§", payload, template_body)

    def one(payload: str) -> dict:
        url = build_url(payload)
        body = build_body(payload)
        resp = _send(req.method, url, req.headers, body,
                     timeout=timeout)
        return {
            "payload": payload,
            "url": url,
            **resp.to_dict(include_body=False),
        }

    results: list[dict] = []
    workers = max(1, min(20, int(workers or 1)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for r in pool.map(one, payloads):
            results.append(r)

    # Classify: distinct statuses, unexpected sizes, errors.
    statuses = sorted({r["status"] for r in results})
    anomalies = [r for r in results if r["status"] not in (200, 302, 404, 500)
                 or r["error"]]
    return {
        "ok": True,
        "total": len(results),
        "distinct_statuses": statuses,
        "by_status": {
            str(s): sum(1 for r in results if r["status"] == s)
            for s in statuses
        },
        "anomalies": anomalies[:50],
        "sample": results[:20],
    }


class _LinkExtractor(html.parser.HTMLParser):
    """Collect absolute links from an HTML document."""

    def __init__(self, base: str):
        super().__init__()
        self.base = base
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        for key, value in attrs:
            if key in ("href", "src") and value:
                self.links.append(urllib.parse.urljoin(self.base, value))


def spider(start_url: str, max_pages: int = SPIDER_MAX_PAGES,
           timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Crawl a site from a seed URL, same-origin only, breadth-first."""
    if not urllib.parse.urlparse(start_url).scheme:
        return {"ok": False, "error": "url must include a scheme (http/https)"}
    base = f"{urllib.parse.urlparse(start_url).scheme}://{urllib.parse.urlparse(start_url).netloc}"
    seen: set = set()
    queue: list[str] = [start_url]
    pages: list[dict] = []
    errors: list[dict] = []
    max_pages = min(int(max_pages) or SPIDER_MAX_PAGES, SPIDER_MAX_PAGES)

    while queue and len(pages) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        resp = _send("GET", url, {}, "", timeout)
        if resp.error or not resp.body:
            errors.append({"url": url, "error": resp.error or "empty body",
                           "status": resp.status})
            continue
        pages.append({
            "url": url,
            "status": resp.status,
            "chars": len(resp.body),
            "title": _title(resp.body),
            "content_type": resp.headers.get("Content-Type", ""),
        })
        parser = _LinkExtractor(url)
        try:
            parser.feed(resp.body)
        except Exception:  # noqa: BLE001, S110 - a bad page must not kill the crawl
            pass
        for link in parser.links:
            parsed = urllib.parse.urlparse(link)
            if parsed.scheme not in ("http", "https"):
                continue
            if f"{parsed.scheme}://{parsed.netloc}" != base:
                continue  # stay on the same origin
            if link not in seen:
                queue.append(link)

    return {
        "ok": True,
        "seed": start_url,
        "pages_crawled": len(pages),
        "pages": pages[:SPIDER_MAX_PAGES],
        "errors": errors[:50],
    }


def _title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""


class LabProxy:
    """Tiny forward HTTP proxy for the local lab.

    Listens on host:port, forwards each request as-is, applies match-replace
    rules to request bodies, and logs everything to a bounded ring buffer.
    Use on localhost for authorized testing only.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8080,
                 rules: list[dict] | None = None,
                 max_requests: int = 1_000):
        self.host = host
        self.port = port
        self.rules = rules or []
        self.max_requests = max_requests
        self.logs: list[dict] = []
        self._lock = threading.Lock()
        # _ProxyServer is a nested class created in start(); Any keeps the
        # annotation stable across the lifecycle (None before start).
        self._server: Any = None
        self._thread: threading.Thread | None = None
        self._stop = False

    def start(self) -> dict:
        """Bind and listen in a background thread."""
        import socketserver

        class _LabHandler(socketserver.StreamRequestHandler):
            def handle(self):  # noqa: D401 - socket API
                try:
                    self._handle()
                except Exception as exc:  # noqa: BLE001 - proxy must survive
                    self.server._record({
                        "error": str(exc)[:200],
                        "method": "",
                        "url": "",
                    })

            def _handle(self):
                line = self.rfile.readline().decode("latin-1").strip()
                if not line:
                    return
                parts = line.split(" ")
                if len(parts) < 3:
                    return
                method, url, _version = parts[0], parts[1], parts[2]
                headers = {}
                content_length = 0
                while True:
                    h = self.rfile.readline().decode("latin-1").strip()
                    if not h:
                        break
                    key, _, value = h.partition(":")
                    headers[key.strip().lower()] = value.strip()
                    if key.lower() == "content-length":
                        try:
                            content_length = int(value)
                        except ValueError:
                            content_length = 0
                body = ""
                if content_length > 0:
                    body = self.rfile.read(
                        min(content_length, PROXY_MAX_BODY)
                    ).decode("latin-1", errors="replace")
                body = apply_match_rules(self.server.rules, body)

                resp = _send(method, url, headers, body, timeout=30)
                self.server._record({
                    "method": method, "url": url, "status": resp.status,
                    "body_chars": len(body),
                    "duration_s": round(resp.duration_s, 3),
                })
                self.wfile.write(
                    f"HTTP/1.1 {resp.status} {_reason(resp.status)}\r\n".encode("latin-1")
                )
                for key, value in resp.headers.items():
                    if key.lower() in ("transfer-encoding", "connection"):
                        continue
                    self.wfile.write(f"{key}: {value}\r\n".encode("latin-1"))
                self.wfile.write(b"Content-Length: "
                                 + str(len(resp.body)).encode() + b"\r\n\r\n")
                self.wfile.write(resp.body.encode("latin-1", errors="replace"))

        class _ProxyServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

            def __init__(self, server_address, handler_class, rules,
                         max_requests):
                self.rules = rules
                self.max_requests = max(1, max_requests)
                self._logs = []
                self._lock = threading.Lock()
                super().__init__(server_address, handler_class)

            def _record(self, entry: dict):
                with self._lock:
                    self._logs.append(entry)
                    del self._logs[:-self.max_requests]

            def logs(self):
                with self._lock:
                    return list(self._logs)

        self._server = _ProxyServer(
            (self.host, self.port), _LabHandler, self.rules, self.max_requests
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()
        return {"ok": True, "host": self.host, "port": self.port,
                "pid": None}

    def stop(self) -> dict:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        return {"ok": True}

    def request_logs(self) -> list:
        return list(self._server.logs()) if self._server else []


def _reason(status: int) -> str:
    return {200: "OK", 201: "Created", 204: "No Content", 301: "Moved Permanently",
            302: "Found", 304: "Not Modified", 400: "Bad Request", 401: "Unauthorized",
            403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
            429: "Too Many Requests", 500: "Internal Server Error",
            502: "Bad Gateway", 503: "Service Unavailable"}.get(status, "OK")
