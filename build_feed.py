#!/usr/bin/env python3

# Watcha looking for?

import calendar, json, re, sys, time
from datetime import datetime, timezone

import feedparser
import requests

FEEDS = [
    ("CIS Advisories",    "https://www.cisecurity.org/feed/advisories"),
    ("SANS ISC",          "https://isc.sans.edu/rssfeed.xml"),
    ("The Hacker News",   "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer",  "https://www.bleepingcomputer.com/feed/"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("Dark Reading",      "https://www.darkreading.com/rss.xml"),
    ("SecurityWeek",      "https://feeds.feedburner.com/securityweek"),
    ("Cisco Talos",       "https://blog.talosintelligence.com/rss/"),
    ("Unit 42",           "https://unit42.paloaltonetworks.com/feed/"),
    ("Google GTIG",       "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/"),
    ("RF The Record",     "https://therecord.media/feed"),

]

MAX_PER_FEED = 15
UA = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
UA_FALLBACK = {
    "User-Agent": "Mozilla/5.0 (compatible; OSINT-Watchfloor/1.0; +https://github.com)",
    "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.8",
}
TAG_RE = re.compile(r"<[^>]+>")
CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MAX_BYTES = 5 * 1024 * 1024  

def fetch_capped(session: requests.Session, url: str) -> bytes:
    for headers in (UA, UA_FALLBACK):
        with session.get(url, headers=headers, timeout=20, stream=True, verify=True) as resp:
            if resp.status_code == 403:
                continue  # try next header set
            resp.raise_for_status()
            buf = b""
            for chunk in resp.iter_content(64 * 1024):
                buf += chunk
                if len(buf) > MAX_BYTES:
                    raise ValueError(f"response exceeded {MAX_BYTES} bytes")
            return buf
    raise ValueError("403 with all header profiles")

def safe_link(url: str) -> str:
    return url if isinstance(url, str) and url.startswith(("https://", "http://")) else ""

def clean(html: str, limit: int = 220) -> str:
    text = CTRL_RE.sub("", TAG_RE.sub("", html or ""))
    return re.sub(r"\s+", " ", text).strip()[:limit]

IMG_SRC_RE = re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.I)

def extract_image(e) -> str:
    """Best-effort thumbnail from RSS-embedded media. https-only."""
    candidates = []
    for m in getattr(e, "media_thumbnail", []) or []:
        candidates.append(m.get("url", ""))
    for m in getattr(e, "media_content", []) or []:
        if "image" in (m.get("medium") or m.get("type") or "image"):
            candidates.append(m.get("url", ""))
    for l in getattr(e, "links", []) or []:
        if l.get("rel") == "enclosure" and str(l.get("type", "")).startswith("image/"):
            candidates.append(l.get("href", ""))
    html = getattr(e, "summary", "") or ""
    m = IMG_SRC_RE.search(html)
    if m:
        candidates.append(m.group(1))
    for c in candidates:
        if isinstance(c, str) and c.startswith("https://"):
            return c[:500]
    return ""

def entry_date(e) -> str:
    for attr in ("published_parsed", "updated_parsed"):
        t = getattr(e, attr, None)
        if t:
            return datetime.fromtimestamp(calendar.timegm(t), tz=timezone.utc).isoformat()
    return datetime.now(tz=timezone.utc).isoformat()

def main() -> int:
    items, failed = [], []
    session = requests.Session()
    session.max_redirects = 5
    for name, url in FEEDS:
        try:
            parsed = feedparser.parse(fetch_capped(session, url))
            if not parsed.entries:
                raise ValueError("no entries parsed")
            for e in parsed.entries[:MAX_PER_FEED]:
                link = safe_link(getattr(e, "link", ""))
                title = clean(getattr(e, "title", ""), 300)
                if not (link and title):
                    continue
                items.append({
                    "source": name,
                    "title": title,
                    "link": link,
                    "desc": clean(getattr(e, "summary", "")),
                    "image": extract_image(e),
                    "date": entry_date(e),
                })
            print(f"ok   {name}")
        except Exception as exc:
            failed.append(name)
            print(f"FAIL {name}: {exc}", file=sys.stderr)

    items.sort(key=lambda i: i["date"], reverse=True)
    out = {
        "generated": datetime.now(tz=timezone.utc).isoformat(),
        "sources_ok": len(FEEDS) - len(failed),
        "sources_total": len(FEEDS),
        "failed": failed,
        "items": items,
    }
    with open("feed.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(f"wrote feed.json: {len(items)} items, {len(failed)} failed")
    return 0 if items else 1

if __name__ == "__main__":
    sys.exit(main())