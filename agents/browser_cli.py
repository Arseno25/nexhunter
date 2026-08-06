"""nexhunter.agents.browser_cli - headless browser crawl for the registry tool.

Runs as `python -m nexhunter.agents.browser_cli -u <url> ...` from the
ExecutionService. Two engines:

1. Selenium + Chrome/Chromium (if installed) - real JS runtime, deep DOM,
   network request log, screenshots, anti-detection preamble.
2. Stdlib urllib + HTMLParser fallback - static HTML only, no JS.

Output is a single JSON document on stdout so the registry parser
(browser_json) can consume it. If Selenium is missing the tool degrades
gracefully: it crawls statically and says so in the JSON.
"""

import argparse
import json
import re
import sys
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

OUT: dict[str, object] = {
    "ok": False,
    "engine": None,
    "url": None,
    "status": 0,
    "title": "",
    "links": [],
    "scripts_found": 0,
    "headers": {},
    "dom_depth": 0,
    "forms_found": 0,
    "screenshot": False,
    "note": "",
    "error": None,
}

# Anti-detection preamble: hides headless automation from window checks that
# JS frameworks and WAFs use (navigator.webdriver, chrome properties). It also
# installs the JS runtime collectors so pages that crash under analysis can be
# diagnosed. Kept as one string; executed via CDP before page scripts run.
ANTI_DETECT_JS = r"""
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
window.chrome = window.chrome || {runtime: {}};
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
const origQuery = window.navigator.permissions && window.navigator.permissions.query;
if (origQuery) {
  window.navigator.permissions.query = (p) =>
    p && p.name === 'notifications'
      ? Promise.resolve({state: Notification.permission})
      : origQuery(p);
}
window.__nexhunter_js_errors = [];
window.__nexhunter_console_warnings = [];
window.addEventListener('error', (e) => window.__nexhunter_js_errors.push(String(e.message)));
window.addEventListener('unhandledrejection', (e) =>
  window.__nexhunter_js_errors.push('unhandledrejection: ' + String(e.reason)));
const __nxConsoleError = console.error.bind(console);
console.error = (...args) => {
  window.__nexhunter_console_warnings.push(args.map(String).join(' '));
  __nxConsoleError(...args);
};
"""


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.scripts = 0
        self.forms = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        elif tag == "script":
            self.scripts += 1
        elif tag == "form":
            self.forms += 1


def _static_crawl(url: str, wait: int) -> None:
    """Fallback engine: urllib + HTMLParser, no JavaScript execution."""
    import urllib.request

    OUT["engine"] = "stdlib"
    OUT["url"] = url
    OUT["note"] = (
        "selenium not installed; static crawl only, no JS execution. Install with: pip install nexhunter[browser]"
    )
    if urlparse(url).scheme not in ("http", "https"):
        OUT["error"] = f"refusing non-http(s) url: {url}"
        return
    req = urllib.request.Request(url, headers={"User-Agent": "nexhunter/2.0 (+https://github.com/Arseno25/nexhunter)"})  # noqa: S310 - scheme validated above
    try:
        with urllib.request.urlopen(req, timeout=max(10, wait)) as resp:  # nosec B310 - http/https only, scheme validated above
            body = resp.read(65536).decode("utf-8", errors="replace")
            OUT["status"] = resp.status
            OUT["headers"] = {k: v for k, v in resp.headers.items()}
    except Exception as exc:  # noqa: BLE001 - degraded path reports, not raises
        OUT["error"] = f"static fetch failed: {exc}"
        return
    parser = _LinkParser()
    parser.feed(body)
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", body)
    OUT["title"] = m.group(1).strip() if m else ""
    OUT["links"] = [urljoin(url, href) for href in parser.links]
    OUT["scripts_found"] = parser.scripts
    OUT["forms_found"] = parser.forms
    OUT["ok"] = True


def _selenium_crawl(url: str, wait: int, screenshot: bool, dom_depth: int) -> None:
    """Selenium engine: real JS runtime, anti-detection, optional screenshot."""
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By

    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_argument("--window-size=1366,768")
    opts.add_argument("--lang=en-US")

    # ponytail: no --user-agent override. headless=new UA has no
    # "HeadlessChrome" token and matches the installed Chrome, so a
    # hardcoded UA would desync Sec-CH-UA vs JS engine (detectable).

    OUT["engine"] = "selenium"
    OUT["url"] = url
    driver = webdriver.Chrome(options=opts)
    try:
        driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": ANTI_DETECT_JS})
        driver.set_page_load_timeout(max(10, wait + 10))
        driver.get(url)
        _wait_settle(driver, wait)

        OUT["status"] = _status_of(driver)
        OUT["title"] = driver.title or ""
        # ponytail: real response headers come from a plain HTTP fetch; the
        # Performance API never exposes responseHeaders. BiDi is the upgrade
        # path if live interception is ever needed.
        OUT["headers"] = _fetch_headers(url, wait)
        OUT["links"] = list(dict.fromkeys(h for h in _gather_links(driver) if _is_http(h)))[:500]
        OUT["scripts_found"] = len(driver.find_elements(By.TAG_NAME, "script"))
        OUT["forms_found"] = len(driver.find_elements(By.TAG_NAME, "form"))
        if dom_depth > 0:
            OUT["dom_depth"] = _measure_dom_depth(driver, dom_depth)
        if screenshot:
            shot = driver.save_screenshot("screenshot.png")
            OUT["screenshot"] = bool(shot)
        OUT["ok"] = True
    except Exception as exc:  # noqa: BLE001 - report, never raise
        OUT["error"] = f"selenium crawl failed: {exc}"
    finally:
        try:
            driver.quit()
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"driver quit failed: {exc}\n")


def _wait_settle(driver, stable_ms: int = 3000, max_ms: int = 8000) -> None:
    """Explicit wait for dynamic content: polls until the resource count
    stops growing, so SPAs that render after XHRs are captured. Replaces
    implicit waits/fixed sleeps (Selenium best practice)."""
    try:
        driver.execute_async_script(
            "const done = arguments[arguments.length - 1];"
            "const stableMs = arguments[0];"
            "const maxMs = arguments[1];"
            "let last = 0, t0 = Date.now();"
            "const check = () => {"
            "  const n = performance.getEntriesByType('resource').length;"
            "  const elapsed = Date.now() - t0;"
            "  if (elapsed > maxMs || (n === last && elapsed > stableMs)) return done();"
            "  last = n; setTimeout(check, 250);"
            "};"
            "check();",
            stable_ms,
            max_ms,
        )
    except Exception:  # noqa: BLE001, S110 - settle wait is best-effort
        pass


def _fetch_headers(url: str, wait: int) -> dict:
    """Real response headers for the document, via a plain HTTP request."""
    import urllib.request

    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "nexhunter/2.0 (+https://github.com/Arseno25/nexhunter)"}
        )  # noqa: S310 - scheme validated in _is_http
        with urllib.request.urlopen(req, timeout=max(10, wait)) as resp:  # nosec B310 - http/https only
            return {k: v for k, v in resp.headers.items()}
    except Exception:  # noqa: BLE001
        return {}


def _status_of(driver) -> int:
    for entry in _performance_entries(driver):
        if entry.get("responseStatus"):
            return entry["responseStatus"]
    return 0


def _performance_entries(driver) -> list:
    try:
        return driver.execute_script("return performance.getEntriesByType('resource').map(e => e.toJSON())") or []
    except Exception:  # noqa: BLE001
        return []


def _gather_links(driver) -> list:
    try:
        return driver.execute_script("return Array.from(document.querySelectorAll('a[href]')).map(a => a.href)") or []
    except Exception:  # noqa: BLE001
        return []


def _measure_dom_depth(driver, limit: int) -> int:
    try:
        return int(
            driver.execute_script(
                "let d=0;function w(n,l){l++;if(l>d)d=l;for(const c of n.children)w(c,l)}w(document.body,0);return d;"
            )
            or 0
        )
    except Exception:  # noqa: BLE001
        return 0


def _is_http(href: str) -> bool:
    scheme = urlparse(href).scheme.lower()
    return scheme in ("http", "https")


def _load_dom_depth(args) -> int:
    return max(0, int(args.dom_depth or 0))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="nexhunter browser crawl")
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("--wait", type=int, default=3)
    parser.add_argument("--screenshot", action="store_true")
    parser.add_argument("--dom-depth", type=int, default=0)
    args = parser.parse_args(argv)

    OUT["url"] = args.url
    try:
        import selenium  # noqa: F401

        _selenium_crawl(args.url, args.wait, args.screenshot, _load_dom_depth(args))
    except ImportError:
        _static_crawl(args.url, args.wait)

    print(json.dumps(OUT, ensure_ascii=False))
    return 0 if OUT["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
