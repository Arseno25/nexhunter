"""nexhunter.agents.browser_cli - headless browser crawl for the registry tool.

Runs as `python -m nexhunter.agents.browser_cli -u <url> ...` from the
ExecutionService. Two engines:

1. Selenium + Chrome/Chromium (if installed) - real JS runtime, deep DOM,
   network request log, screenshots, anti-detection preamble.
2. Stdlib urllib + HTMLParser fallback - static HTML only, no JS.

Output is a single JSON document on stdout so the registry parser
(browser_json) can consume it. If Selenium is missing the tool degrades
gracefully: it crawls statically and says so in the JSON.

The engines live in nexhunter.agents.browser; this CLI is a thin wrapper
that keeps the registry tool's JSON contract (keys below).
"""

import argparse
import json
import sys
from urllib.parse import urljoin, urlparse

from nexhunter.agents.browser import (
    ANTI_DETECT_JS,
    _DomParser,
    _StaticFetcher,
    _gather_links,
    _measure_dom_depth,
    _status_of,
    _title_of,
    _wait_settle,
)

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


def _static_crawl(url: str, wait: int) -> None:
    """Fallback engine: urllib + HTMLParser, no JavaScript execution."""
    OUT["engine"] = "stdlib"
    OUT["url"] = url
    OUT["note"] = (
        "selenium not installed; static crawl only, no JS execution. Install with: pip install nexhunter[browser]"
    )
    if urlparse(url).scheme not in ("http", "https"):
        OUT["error"] = f"refusing non-http(s) url: {url}"
        return
    fetcher = _StaticFetcher(url, timeout=max(10, wait))
    if not fetcher.fetch():
        OUT["error"] = fetcher.error or "static fetch failed"
        return
    parser = _DomParser()
    parser.feed(fetcher.html)
    OUT["status"] = fetcher.status
    OUT["headers"] = fetcher.headers
    OUT["title"] = _title_of(fetcher.html)
    OUT["links"] = [urljoin(url, href) for href in parser.links]
    OUT["scripts_found"] = len(parser.scripts)
    OUT["forms_found"] = len(parser.forms)
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
        # wait is CLI seconds; _wait_settle works in milliseconds.
        _wait_settle(driver, wait * 1000)

        OUT["status"] = _status_of(driver)
        OUT["title"] = driver.title or ""
        # ponytail: real response headers come from a plain HTTP fetch; the
        # Performance API never exposes responseHeaders. BiDi is the upgrade
        # path if live interception is ever needed.
        static = _StaticFetcher(url, timeout=max(10, wait))
        OUT["headers"] = static.headers if static.fetch() else {}
        OUT["links"] = list(dict.fromkeys(h for h in _gather_links(driver) if _is_http(h)))[:500]
        OUT["scripts_found"] = len(driver.find_elements(By.TAG_NAME, "script"))
        OUT["forms_found"] = len(driver.find_elements(By.TAG_NAME, "form"))
        if dom_depth > 0:
            OUT["dom_depth"] = _measure_dom_depth(driver)
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
    if urlparse(args.url).scheme not in ("http", "https"):
        OUT["error"] = f"refusing non-http(s) url: {args.url}"
        print(json.dumps(OUT, ensure_ascii=False))
        return 1
    try:
        import selenium  # noqa: F401

        _selenium_crawl(args.url, args.wait, args.screenshot, _load_dom_depth(args))
    except ImportError:
        _static_crawl(args.url, args.wait)

    print(json.dumps(OUT, ensure_ascii=False))
    return 0 if OUT["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
