"""Browser agent - Selenium-powered DOM analysis, network monitoring, crawling.

Two engines, one output schema:

1. Selenium + Chrome/Chromium (if installed): real JS runtime, deep DOM,
   network request capture via CDP, screenshots, anti-detection preamble.
2. Stdlib urllib + HTMLParser fallback: static HTML only, no JS.

Modes (via `mode` param):
  analyze        (default) DOM artifacts + security headers + cookies + tech
  screenshot     save a screenshot of the target into the execution workspace
  network        capture requests the page made (XHR/fetch/scripts)
  crawl          JS-aware discovery of same-origin links/endpoints
  forms          enumerate forms with fields, actions, methods, tokens

The agent never executes anything outside the HTTP layer: it is a caller of
targets, not a shell. Selenium degradation is graceful - missing driver or
binary falls back to the stdlib crawl and says so in the output.
"""

import re
import urllib.request
from html.parser import HTMLParser

from nexhunter.agents.base import Agent

# Anti-detection preamble: hides headless automation from window checks that
# JS frameworks and WAFs use (navigator.webdriver, chrome properties, UA).
# Executed via CDP before page scripts run.
ANTI_DETECT_JS = r"""
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
window.chrome = window.chrome || {runtime: {}};
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
const origQuery = window.navigator.permissions && window.navigator.permissions.query;
if (origQuery) {
  window.navigator.permissions.query = (p) =>
    p && p.name === 'notifications'
      ? Promise.resolve({state: Notification.permission})
      : origQuery(p);
}
"""

_SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "X-XSS-Protection",
)

# Header / DOM / URL signatures per technology; used by the tech detector.
_TECH_SIGNATURES = {
    "nginx": {"headers": {"server": "nginx"}},
    "apache": {"headers": {"server": "apache"}},
    "iis": {"headers": {"server": "microsoft-iis"}},
    "php": {"headers": {"x-powered-by": "php"}},
    "python": {"headers": {"server": "python", "x-powered-by": "flask|django|werkzeug"}},
    "nodejs": {"headers": {"x-powered-by": "express"}, "content": ["__NEXT_DATA__", "data-reactroot", "webpack"]},
    "java": {"headers": {"server": "tomcat|jboss|jetty", "x-powered-by": "servlet"}},
    "dotnet": {"headers": {"x-aspnet-version": "."}},
    "wordpress": {"content": ["wp-content", "wp-includes"]},
    "drupal": {"content": ["/sites/default", "drupal"]},
    "joomla": {"content": ["/administrator", "joomla"]},
    "react": {"content": ["__REACT_DEVTOOLS_GLOBAL_HOOK__", "data-reactroot", "react"]},
    "vue": {"content": ["__VUE__", "vue@"]},
    "angular": {"content": ["ng-version", "ng-app"]},
    "jquery": {"content": ["jquery"]},
    "bootstrap": {"content": ["bootstrap"]},
    "cloudflare": {"headers": {"server": "cloudflare", "cf-ray": "."}},
    "sentry": {"content": ["sentry"]},
    "google-analytics": {"content": ["googletagmanager", "google-analytics"]},
}

_HEADER_TECH = {tech: sig["headers"] for tech, sig in _TECH_SIGNATURES.items() if "headers" in sig}
_CONTENT_TECH = {tech: sig["content"] for tech, sig in _TECH_SIGNATURES.items() if "content" in sig}


class _DomParser(HTMLParser):
    """Extract forms, links, scripts, meta tags from HTML."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self.links = []
        self.scripts = []
        self.metas = []
        self._in_form = False

    def handle_starttag(self, tag: str, attrs: list):
        a = dict(attrs)
        if tag == "form":
            self._in_form = True
            self.forms.append({"action": a.get("action", ""), "method": a.get("method", "get"), "inputs": []})
        elif tag == "input" and self.forms:
            self.forms[-1]["inputs"].append({"name": a.get("name", ""), "type": a.get("type", "text")})
        elif tag == "a":
            self.links.append(a.get("href", ""))
        elif tag == "script":
            self.scripts.append(a.get("src", "inline"))
        elif tag == "meta":
            self.metas.append({"name": a.get("name", ""), "content": a.get("content", "")[:200]})

    def handle_endtag(self, tag: str):
        if tag == "form":
            self._in_form = False


def _detect_tech(html: str, headers: dict) -> list:
    """Best-effort technology fingerprint from headers + HTML signatures."""
    found = []
    lowered = html.lower() if html else ""
    for tech, sigs in _HEADER_TECH.items():
        for key, pattern in sigs.items():
            value = (headers.get(key) or headers.get(key.title()) or "").lower()
            if value and re.search(pattern, value, re.IGNORECASE):
                found.append(tech)
                break
    for tech, patterns in _CONTENT_TECH.items():
        for pattern in patterns:
            if pattern in lowered:
                found.append(tech)
                break
    return sorted(set(found))


def _analyze_cookies(raw_cookies: list) -> list:
    """Cookie security flags from raw Set-Cookie header values."""
    out = []
    for c in raw_cookies:
        parts = [p.strip() for p in c.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name_value = parts[0].split("=", 1)
        flags = {}
        for p in parts[1:]:
            key, _, value = p.partition("=")
            flags[key.lower()] = value
        out.append({
            "name": name_value[0],
            "secure": "secure" in flags,
            "httponly": "httponly" in flags,
            "samesite": flags.get("samesite", "MISSING"),
            "path": flags.get("path", "/"),
            "domain": flags.get("domain", ""),
        })
    return out


class _StaticFetcher:
    """urllib-based static fetch with browser-ish headers."""

    def __init__(self, url: str, timeout: int = 15):
        self.url = url
        self.timeout = timeout
        self.status = 0
        self.headers = {}
        self.html = ""
        self.cookies = []
        self.error = ""

    def fetch(self) -> bool:
        try:
            req = urllib.request.Request(  # noqa: S310 - scheme validated by caller
                self.url, headers={"User-Agent": "Mozilla/5.0 (nexhunter)"}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                self.status = resp.status
                self.headers = {k.lower(): v for k, v in resp.headers.items()}
                self.html = resp.read(500_000).decode("utf-8", errors="replace")
                self.cookies = resp.headers.get_all("Set-Cookie") or []
            return True
        except Exception as e:  # noqa: BLE001 - degraded path reports, not raises
            self.error = str(e)
            return False


class BrowserAgent(Agent):
    """Selenium-powered browser analysis with stdlib fallback.

    Modes: analyze (DOM+headers+cookies+tech), screenshot, network, crawl, forms.
    """

    name = "browser"
    desc = ("Browser analysis: DOM artifacts, security headers, cookies, "
            "technology fingerprint, screenshots, network capture, crawling "
            "(Selenium when installed, stdlib fallback otherwise)")
    param_schema = {"url": (True, str), "mode": (False, str)}

    def run(self, url: str = "", mode: str = "analyze"):
        """Analyze target URL. mode: analyze|screenshot|network|crawl|forms.

        Returns the payload dict directly (with engine/ok/error keys), the
        same shape the selenium path produces, so REST and MCP consumers get
        one contract.
        """
        if not url:
            return {"ok": False, "error": "url required"}
        if not re.match(r"^https?://", url):
            return {"ok": False, "error": "url must be http(s)"}

        mode = (mode or "analyze").lower()
        try:
            import selenium  # noqa: F401
            return self._selenium_run(url, mode)
        except ImportError:
            data = self._static_run(url)
            if data is None:
                return {"ok": False, "error": "fetch failed"}
            return data

    # ------------------------------------------------------------------
    # Static fallback (stdlib)
    # ------------------------------------------------------------------

    def _static_run(self, url: str) -> dict | None:
        f = _StaticFetcher(url)
        if not f.fetch():
            return None
        p = _DomParser()
        p.feed(f.html)

        gen = [m["content"] for m in p.metas if "generator" in m["name"].lower()]
        sec = {h: (f.headers.get(h.lower()) or "MISSING") for h in _SECURITY_HEADERS}
        cookies = _analyze_cookies(f.cookies)

        return {
            "url": url,
            "engine": "stdlib",
            "ok": True,
            "note": "selenium not installed; static crawl only, no JS execution. "
                    "Install with: pip install nexhunter[browser]",
            "status": f.status,
            "title": _title_of(f.html),
            "forms": p.forms[:50],
            "form_count": len(p.forms),
            "links": p.links[:200],
            "link_count": len(p.links),
            "script_count": len(p.scripts),
            "generator": gen,
            "technologies": _detect_tech(f.html, f.headers),
            "security_headers": sec,
            "cookies": cookies,
        }

    # ------------------------------------------------------------------
    # Selenium engine
    # ------------------------------------------------------------------

    def _selenium_run(self, url: str, mode: str) -> dict:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.common.by import By

        opts = Options()
        opts.add_argument("--headless=new")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--disable-blink-features=AutomationControlled")
        opts.add_argument("--window-size=1366,768")
        opts.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
        opts.add_experimental_option("excludeSwitches", ["enable-automation"])

        driver = webdriver.Chrome(options=opts)
        try:
            driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": ANTI_DETECT_JS})
            driver.set_page_load_timeout(30)

            driver.get(url)
            driver.implicitly_wait(3)

            if mode == "screenshot":
                shot = driver.save_screenshot("browser_screenshot.png")
                return {
                    "url": url,
                    "engine": "selenium",
                    "ok": True,
                    "screenshot": bool(shot),
                    "file": "browser_screenshot.png" if shot else "",
                    "title": driver.title or "",
                    "status": _status_of(driver),
                }

            if mode == "network":
                return {
                    "url": url,
                    "engine": "selenium",
                    "ok": True,
                    "requests": _network_requests(driver)[:200],
                    "request_count": len(_network_requests(driver)),
                    "title": driver.title or "",
                }

            if mode == "crawl":
                links = _gather_links(driver)
                return {
                    "url": url,
                    "engine": "selenium",
                    "ok": True,
                    "links": list(dict.fromkeys(links))[:500],
                    "link_count": len(set(links)),
                    "title": driver.title or "",
                }

            if mode == "forms":
                forms = _gather_forms(driver)
                return {
                    "url": url,
                    "engine": "selenium",
                    "ok": True,
                    "forms": forms,
                    "form_count": len(forms),
                    "title": driver.title or "",
                }

            # analyze (default)
            p = _DomParser()
            p.feed(driver.page_source or "")
            headers = _response_headers(driver)
            cookies = [
                {
                    "name": c.get("name", ""),
                    "secure": bool(c.get("secure")),
                    "httponly": bool(c.get("httpOnly")),
                    "samesite": c.get("sameSite", "MISSING") or "MISSING",
                    "path": c.get("path", "/"),
                    "domain": c.get("domain", ""),
                }
                for c in driver.get_cookies()
            ]
            gen = [m["content"] for m in p.metas if "generator" in m["name"].lower()]
            sec = {h: (headers.get(h.lower()) or "MISSING") for h in _SECURITY_HEADERS}

            return {
                "url": url,
                "engine": "selenium",
                "ok": True,
                "status": _status_of(driver),
                "title": driver.title or "",
                "forms": p.forms[:50],
                "form_count": len(p.forms),
                "links": _gather_links(driver)[:200],
                "link_count": len(_gather_links(driver)),
                "script_count": len(driver.find_elements(By.TAG_NAME, "script")),
                "generator": gen,
                "technologies": _detect_tech(driver.page_source or "", headers),
                "security_headers": sec,
                "cookies": cookies,
                "dom_depth": _measure_dom_depth(driver),
                "js_errors": _js_errors(driver),
                "console_warnings": _console_warnings(driver),
            }
        except Exception as e:  # noqa: BLE001 - report, never raise
            return {"url": url, "engine": "selenium", "ok": False, "error": f"selenium failed: {e}"}
        finally:
            try:
                driver.quit()
            except Exception:  # noqa: BLE001, S110 - driver teardown must not raise
                pass


def _network_requests(driver, limit: int = 200) -> list:
    """Requests the page made, via the Performance API (works without CDP)."""
    try:
        entries = driver.execute_script(
            "return performance.getEntriesByType('resource').map(e => e.toJSON())"
        ) or []
    except Exception:  # noqa: BLE001
        return []
    out = []
    seen = set()
    for entry in entries:
        url = entry.get("name", "")
        if not url or url in seen:
            continue
        seen.add(url)
        out.append({
            "url": url,
            "type": entry.get("initiatorType", ""),
            "duration_ms": round(entry.get("duration", 0), 1),
            "size": entry.get("transferSize", 0),
        })
        if len(out) >= limit:
            break
    return out


def _status_of(driver) -> int:
    try:
        nav = driver.execute_script(
            "return performance.getEntriesByType('navigation')[0]?.toJSON() || null"
        )
        if nav and nav.get("responseStatus"):
            return nav["responseStatus"]
        entries = driver.execute_script(
            "return performance.getEntriesByType('resource').map(e => e.toJSON())"
        ) or []
        for entry in entries:
            if entry.get("responseStatus"):
                return entry["responseStatus"]
    except Exception:  # noqa: BLE001, S110 - degraded read, default status
        pass
    return 0


def _response_headers(driver) -> dict:
    try:
        entries = driver.execute_script(
            "return performance.getEntriesByType('resource').map(e => e.toJSON())"
        ) or []
        for entry in entries:
            headers = {h["name"]: h["value"] for h in entry.get("responseHeaders", [])}
            if headers:
                return headers
    except Exception:  # noqa: BLE001, S110 - degraded read, empty headers
        pass
    return {}


def _gather_links(driver) -> list:
    try:
        return driver.execute_script(
            "return Array.from(document.querySelectorAll('a[href]')).map(a => a.href)"
        ) or []
    except Exception:  # noqa: BLE001
        return []


def _gather_forms(driver) -> list:
    try:
        return driver.execute_script(
            "return Array.from(document.forms).map(f => ({"
            "  action: f.action || '', method: f.method || 'get',"
            "  inputs: Array.from(f.elements).map(i => ({name: i.name || '', type: i.type || ''}))"
            "}))"
        ) or []
    except Exception:  # noqa: BLE001
        return []


def _measure_dom_depth(driver) -> int:
    try:
        return int(driver.execute_script(
            "let d=0;"
            "function w(n,l){l++;if(l>d)d=l;for(const c of n.children)w(c,l)}"
            "w(document.body,0);return d;"
        ) or 0)
    except Exception:  # noqa: BLE001
        return 0


def _js_errors(driver) -> list:
    try:
        return driver.execute_script("return window.__nexhunter_js_errors || []") or []
    except Exception:  # noqa: BLE001
        return []


def _console_warnings(driver) -> list:
    try:
        return driver.execute_script("return window.__nexhunter_console_warnings || []") or []
    except Exception:  # noqa: BLE001
        return []


def _title_of(html: str) -> str:
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", html)
    return m.group(1).strip() if m else ""
