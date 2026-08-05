"""
ioc_extract.py: server-side IoC extraction for OSINT Watchfloor.

Pure stdlib baby.

  * Output is defanged by default. These files open in a browser tab; a live
    clickable malicious URL is a footgun.
"""

import html as html_lib
import ipaddress
import re
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Denylists - benign infrastructure that should never surface as an indicator.
# Suffix-based matching: "google.com" also kills "fonts.google.com".
# ---------------------------------------------------------------------------
DENY_DOMAINS = {
    # news / the feed's own sources
    "bleepingcomputer.com", "thehackernews.com", "krebsonsecurity.com",
    "securityweek.com", "darkreading.com", "therecord.media", "sans.edu",
    "isc.sans.edu", "cisa.gov", "ic3.gov", "us-cert.gov", "cert.org",
    # platforms / CDNs / infra that show up in every article's markup
    "google.com", "gstatic.com", "googleapis.com", "youtube.com", "youtu.be",
    "microsoft.com", "windows.com", "office.com", "azure.com", "live.com",
    "apple.com", "amazon.com", "amazonaws.com", "cloudflare.com",
    "cloudfront.net", "akamai.com", "akamaihd.net", "fastly.net",
    "github.com", "githubusercontent.com", "gitlab.com",
    "twitter.com", "x.com", "facebook.com", "fb.com", "linkedin.com",
    "instagram.com", "reddit.com", "mastodon.social", "t.me", "telegram.org",
    "wordpress.com", "wp.com", "gravatar.com", "wikipedia.org",
    "mozilla.org", "w3.org", "schema.org", "creativecommons.org",
    "doubleclick.net", "google-analytics.com", "googletagmanager.com",
    "jsdelivr.net", "unpkg.com", "cdnjs.com", "bootstrapcdn.com",
    "adobe.com", "cisco.com", "oracle.com", "ibm.com", "vmware.com",
    "mitre.org", "nist.gov", "virustotal.com", "shodan.io",
    # feed publishers' own infra + analytics that leak into article pages
    "recordedfuture.com", "talosintelligence.com", "paloaltonetworks.com",
    "bsky.app", "matomo.cloud", "feedburner.com", "withgoogle.com",
    "googleusercontent.com", "substack.com", "medium.com",
    "bleepstatic.com", "informa.com", "typekit.net", "hs-scripts.com",
    "hubspot.com", "onetrust.com", "kubernetes.io", "k8s.io",
}

# Hash-lookup services: their URLs are furniture but the hash inside IS a
# real indicator, so they're exempt from hash-in-URL suppression.
HASH_LOOKUP_HOSTS = ("virustotal.com", "hybrid-analysis.com",
                     "otx.alienvault.com", "abuse.ch", "malwarebazaar",
                     "malshare.com", "joesandbox.com", "any.run")

# TLDs accepted for bare-domain matches. 
COMMON_TLDS = {
    "com","net","org","io","gov","edu","mil","info","biz","co","us","uk",
    "ru","cn","de","fr","nl","eu","xyz","top","site","online","tech","dev",
    "app","cloud","live","me","tv","cc","in","br","jp","kr","au","ca","ir",
    "ua","pl","it","es","se","ch","tk","ml","ga","cf","su","name","pro","sh",
}

FILE_EXT_TAILS = {
    "php","html","htm","asp","aspx","js","css","json","xml","py","exe","dll",
    "txt","pdf","png","jpg","jpeg","gif","svg","zip","rar","doc","docx","md",
}

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
RE_IPV4 = re.compile(r"\b(?:\d{1,3}(?:\[?\.\]?)){3}\d{1,3}\b")
RE_URL = re.compile(r"\bhxxps?://[^\s<>\"')]+|\bhttps?://[^\s<>\"')]+", re.I)
RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\[?\.\]?))+[a-z]{2,24}\b", re.I
)
RE_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
RE_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
RE_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
RE_SHA512 = re.compile(r"\b[a-f0-9]{128}\b", re.I)
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
RE_EMAIL = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b", re.I)

# A token counts as author-defanged if it carries any of these marks.
RE_DEFANG_MARK = re.compile(
    r"\[\.\]|\(\.\)|\[dot\]|\(dot\)|hxxp|\[:\]|\[at\]|\(at\)|\[@\]", re.I
)
RE_HXXP = re.compile(r"hxxp", re.I)
RE_DOT_DEFANG = re.compile(r"\[\.\]|\(\.\)|\[dot\]|\(dot\)", re.I)
RE_AT_DEFANG = re.compile(r"\[at\]|\(at\)|\[@\]", re.I)

RE_SCRIPT_STYLE = re.compile(r"<(script|style)\b.*?</\1\s*>", re.S | re.I)
# Only <pre> blocks (multi-line command/config boxes) are trusted for RAW
# indicators. 
RE_CODE_BLOCK = re.compile(r"<pre\b[^>]*>(.*?)</pre\s*>", re.S | re.I)
RE_TAG = re.compile(r"<[^>]+>")

RE_STATIC_ASSET = re.compile(
    r"\.(?:gif|jpe?g|png|webp|svg|ico|css|js|woff2?|ttf|eot|mp4|webm)(?:$|\?)", re.I
)


def _refang(s: str) -> str:
    """Normalize defanged text back to raw so patterns match consistently."""
    s = re.sub(r"[\u200b\u200c\u200d\ufeff\u00ad]", "", s)  # zero-width / soft hyphen
    s = s.replace("\\u0026", "&").replace("&amp;", "&").replace("&#38;", "&")
    s = RE_DOT_DEFANG.sub(".", s)
    s = RE_AT_DEFANG.sub("@", s)
    s = RE_HXXP.sub("http", s)
    return s.replace("[:]", ":")


def _defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]")


def _defang_domain(d: str) -> str:
    return d.replace(".", "[.]")


def _defang_url(u: str) -> str:
    return u.replace("http", "hxxp").replace(".", "[.]")


def _url_host(u: str) -> str:
    return re.sub(r"^https?://", "", u, flags=re.I).split("/")[0].split("?")[0].split(":")[0].lower()


def _registrable_suffix_hit(host: str, deny: set) -> bool:
    host = host.lower().strip(".")
    parts = host.split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in deny:
            return True
    return False


def extract_iocs(text: str, extra_deny=None, defang: bool = True,
                 code_text: str = "") -> dict:
    """Return {category: sorted[list]} of indicators.

    text: visible article text. Network indicators here must be DEFANGED to
          count; raw ones are treated as citations/furniture.
    code_text: contents of code blocks. Raw network indicators here DO count.
    Hashes and CVEs extract from both regardless.
    """
    if not (text or code_text):
        return {}
    deny = set(DENY_DOMAINS)
    if extra_deny:
        deny |= {d.lower() for d in extra_deny}

    # Pool of author-defanged tokens from visible text, refanged for matching.
    defanged_pool = " ".join(
        _refang(tok) for tok in (text or "").split() if RE_DEFANG_MARK.search(tok)
    )
    code_refanged = _refang(code_text or "")
    net_scan = defanged_pool + " " + code_refanged      # network indicators
    all_refanged = _refang(text or "") + " " + code_refanged  # hashes, CVEs

    urls, ips, domains = set(), set(), set()
    md5s, sha1s, sha256s, sha512s = set(), set(), set(), set()
    cves, emails = set(), set()

    # --- URLs (from defanged visible + code blocks) ---
    url_hosts = set()
    for m in RE_URL.finditer(net_scan):
        u = m.group(0).rstrip(".,);]\\'\"")
        host = _url_host(u)
        if _registrable_suffix_hit(host, deny):
            continue
        if RE_STATIC_ASSET.search(u.split("#")[0]):
            continue  # page furniture: images, scripts, fonts, never IoCs
        url_hosts.add(host)
        urls.add(u)

    # Every URL anywhere (kept, denied, raw, defanged) except hash-lookup
    # services forms the suppression blob for URL-embedded hashes.
    hash_noise = " ".join(
        m.group(0).lower() for m in RE_URL.finditer(all_refanged)
        if not any(h in _url_host(m.group(0)) for h in HASH_LOOKUP_HOSTS)
    )

    # --- IPs (defanged visible + code blocks) ---
    for m in RE_IPV4.finditer(net_scan):
        cand = m.group(0)
        try:
            ip = ipaddress.ip_address(cand)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast \
           or ip.is_link_local or ip.is_unspecified:
            continue
        ips.add(str(ip))

    # --- Emails (defanged visible + code blocks) ---
    for m in RE_EMAIL.finditer(net_scan):
        e = m.group(0).lower()
        dom = e.split("@", 1)[1]
        if _registrable_suffix_hit(dom, deny):
            continue
        emails.add(e)
    email_domains = {e.split("@", 1)[1] for e in emails}

    # --- Bare domains (defanged visible + code blocks) ---
    for m in RE_DOMAIN.finditer(net_scan):
        d = m.group(0).lower().strip(".")
        tld = d.rsplit(".", 1)[-1]
        if tld in FILE_EXT_TAILS or tld not in COMMON_TLDS:
            continue
        if _registrable_suffix_hit(d, deny):
            continue
        if d in url_hosts or d in email_domains:
            continue
        try:
            ipaddress.ip_address(d)
            continue
        except ValueError:
            pass
        domains.add(d)

    # --- CVEs (anywhere) ---
    for m in RE_CVE.finditer(all_refanged):
        cves.add(m.group(0).upper())

    # --- Hashes (anywhere, minus URL-embedded noise, longest-first dedup) ---
    for m in RE_SHA512.finditer(all_refanged):
        h = m.group(0).lower()
        if h in hash_noise:
            continue
        sha512s.add(h)
    # Fragmented SHA-512: some CMSs break long hashes into whitespace-separated
    # hex fragments. Rejoin fragments whose concatenation
    # is exactly 128 hex chars. Guard: reject if any fragment is itself a full
    # hash length (32/40/64/128), otherwise two adjacent listed hashes would
    # merge into a false SHA-512 and consume the real ones via dedup.
    for m in re.finditer(r"\b[a-f0-9]{5,}(?:[ \t\r\n]+[a-f0-9]{5,}){1,5}\b",
                         all_refanged, re.I):
        parts = m.group(0).split()
        if any(len(p) in (32, 40, 64, 128) for p in parts):
            continue
        joined = "".join(parts).lower()
        if len(joined) == 128 and joined not in hash_noise:
            sha512s.add(joined)
    consumed = " ".join(sha512s)
    for m in RE_SHA256.finditer(all_refanged):
        h = m.group(0).lower()
        if h in hash_noise or h in consumed:
            continue
        sha256s.add(h)
    consumed += " " + " ".join(sha256s)
    for m in RE_SHA1.finditer(all_refanged):
        h = m.group(0).lower()
        if h in hash_noise or h in consumed:
            continue
        sha1s.add(h)
    consumed += " " + " ".join(sha1s)
    for m in RE_MD5.finditer(all_refanged):
        h = m.group(0).lower()
        if h in hash_noise or h in consumed:
            continue
        md5s.add(h)

    if defang:
        ips = {_defang_ip(i) for i in ips}
        domains = {_defang_domain(d) for d in domains}
        urls = {_defang_url(u) for u in urls}

    out = {
        "CVEs": sorted(cves),
        "IPv4": sorted(ips),
        "Domains": sorted(domains),
        "URLs": sorted(urls),
        "Emails": sorted(emails),
        "SHA512": sorted(sha512s),
        "SHA256": sorted(sha256s),
        "SHA1": sorted(sha1s),
        "MD5": sorted(md5s),
    }
    return {k: v for k, v in out.items() if v}


def extract_iocs_from_html(html_src: str, title: str = "", desc: str = "",
                           extra_deny=None, defang: bool = True) -> dict:
    """Extract IoCs from a raw article HTML page.

    Strips <script>/<style> content, harvests <pre> block contents (where
    raw indicators are trusted), and defang-gates all other visible text
    including inline <code> spans.
    """
    src = html_src or ""
    no_script = RE_SCRIPT_STYLE.sub(" ", src)
    code_parts = [
        html_lib.unescape(RE_TAG.sub(" ", m.group(1)))
        for m in RE_CODE_BLOCK.finditer(no_script)
    ]
    visible = html_lib.unescape(RE_TAG.sub(" ", RE_CODE_BLOCK.sub(" ", no_script)))
    text = " ".join(filter(None, [title, desc, visible]))
    return extract_iocs(text, extra_deny=extra_deny, defang=defang,
                        code_text=" ".join(code_parts))


def total_count(iocs: dict) -> int:
    return sum(len(v) for v in iocs.values())


def render_txt(iocs: dict, title: str = "", source_url: str = "",
               defanged: bool = True) -> str:
    n = total_count(iocs)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = []
    lines.append(f"IOC EXTRACTION - {title}".rstrip())
    if source_url:
        lines.append(f"Source: {source_url}")
    lines.append(f"Extracted: {ts}")
    lines.append(f"Total indicators: {n}")
    if defanged:
        lines.append("Indicators are DEFANGED (hxxp / [.]). Refang before use.")
    lines.append("Auto-extracted from article text. Verify before acting.")
    lines.append("=" * 64)
    if n == 0:
        lines.append("")
        lines.append("No indicators found in the article text.")
        lines.append("(IoCs may live in a linked vendor report, not the article.)")
        return "\n".join(lines) + "\n"
    for cat, vals in iocs.items():
        lines.append("")
        lines.append(f"{cat} ({len(vals)})")
        lines.append("-" * 40)
        lines.extend(vals)
    return "\n".join(lines) + "\n"