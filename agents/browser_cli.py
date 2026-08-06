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
# JS frameworks and WAFs use (navigator.webdriver, chrome properties, UA).
# Kept as one string; executed via CDP before page scripts run.
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
        "selenium not installed; static crawl only, no JS execution. "
        "Install with: pip install nexhunter[browser]"
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
    opts.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")

    OUT["engine"] = "selenium"
    OUT["url"] = url
    driver = webdriver.Chrome(options=opts)
    try:
        driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": ANTI_DETECT_JS})
        driver.set_page_load_timeout(max(10, wait + 10))
        driver.get(url)
        driver.implicitly_wait(wait)

        OUT["status"] = _status_of(driver)
        OUT["title"] = driver.title or ""
        OUT["headers"] = _response_headers(driver)
        OUT["links"] = list(dict.fromkeys(
            h for h in _gather_links(driver) if _is_http(h)
        ))[:500]
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


def _status_of(driver) -> int:
    for entry in _performance_entries(driver):
        if entry.get("responseStatus"):
            return entry["responseStatus"]
    return 0


def _response_headers(driver) -> dict:
    headers = {}
    for entry in _performance_entries(driver):
        headers = {h["name"]: h["value"] for h in entry.get("responseHeaders", [])}
        if headers:
            break
    return headers


def _performance_entries(driver) -> list:
    try:
        return driver.execute_script(
            "return performance.getEntriesByType('resource').map(e => e.toJSON())"
        ) or []
    except Exception:  # noqa: BLE001
        return []


def _gather_links(driver) -> list:
    try:
        return driver.execute_script(
            "return Array.from(document.querySelectorAll('a[href]')).map(a => a.href)"
        ) or []
    except Exception:  # noqa: BLE001
        return []


def _measure_dom_depth(driver, limit: int) -> int:
    try:
        return int(driver.execute_script(
            "let d=0;"
            "function w(n,l){l++;if(l>d)d=l;for(const c of n.children)w(c,l)}"
            "w(document.body,0);return d;"
        ) or 0)
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
