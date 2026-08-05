"""Browser agent - DOM analysis and HTML parsing."""

import urllib.request
from html.parser import HTMLParser

from nexhunter.agents.base import Agent


class _DomParser(HTMLParser):
    """Extract forms, links, scripts, meta tags from HTML."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self.links = []
        self.scripts = []
        self.metas = []

    def handle_starttag(self, tag: str, attrs: list):
        a = dict(attrs)
        if tag == "form":
            self.forms.append({"action": a.get("action", ""), "method": a.get("method", "get"), "inputs": []})
        elif tag == "input":
            if self.forms:
                self.forms[-1]["inputs"].append({"name": a.get("name", ""), "type": a.get("type", "text")})
        elif tag == "a":
            self.links.append(a.get("href", ""))
        elif tag == "script":
            self.scripts.append(a.get("src", "inline"))
        elif tag == "meta":
            self.metas.append({"name": a.get("name", ""), "content": a.get("content", "")[:120]})


class BrowserAgent(Agent):
    """DOM analysis: forms, links, scripts, generator, security headers, cookies."""

    name = "browser"
    desc = "DOM analysis: forms, links, scripts, generator meta, security headers, cookie flags"
    param_schema = {"url": (True, str)}

    def run(self, url: str = ""):
        """Analyze target URL for DOM artifacts and security headers."""
        if not url:
            return self.result(ok=False, error="url required")

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                html = resp.read().decode(errors="replace")[:500000]
                status = resp.status
                headers = dict(resp.headers.items())
                raw_cookies = resp.headers.get_all("Set-Cookie") or []
        except Exception as e:
            return self.result(ok=False, error=str(e))

        p = _DomParser()
        p.feed(html)

        gen = [m["content"] for m in p.metas if "generator" in m["name"].lower()]
        sec = {
            h: (headers.get(h) or "MISSING")
            for h in ("Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy")
        }
        cookies = [
            {"cookie": c.split(";")[0], "secure": "Secure" in c, "httponly": "HttpOnly" in c}
            for c in raw_cookies
        ]

        return self.result(
            ok=True,
            data={
                "url": url,
                "status": status,
                "forms": p.forms,
                "links": p.links[:100],
                "link_count": len(p.links),
                "script_count": len(p.scripts),
                "generator": gen,
                "security_headers": sec,
                "cookies": cookies,
            },
            meta={"scripts_found": len(p.scripts), "forms_found": len(p.forms)}
        )
