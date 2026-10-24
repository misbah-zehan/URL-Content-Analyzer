import ipaddress
import re
import socket
from collections import Counter
from html import unescape
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from flask import Flask, jsonify, request

app = Flask(__name__)

MAX_BYTES = 2_000_000  # stop reading after ~2 MB
TIMEOUT = 10  # seconds

# ---------- Regular expressions ----------
URL_RE = re.compile(r"^https?://[^\s/$.?#][^\s]*$", re.IGNORECASE)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
META_NAME_RE = re.compile(r'name=["\']([^"\']+)["\']', re.IGNORECASE)
META_CONTENT_RE = re.compile(r'content=["\']([^"\']*)["\']', re.IGNORECASE)
HEADING_RE = re.compile(r"<h([1-3])\b[^>]*>(.*?)</h\1>", re.IGNORECASE | re.DOTALL)
LINK_RE = re.compile(r'<a\b[^>]*?href=["\']([^"\']+)["\']', re.IGNORECASE)
IMG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
IMG_SRC_RE = re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE)
IMG_ALT_RE = re.compile(r'alt=["\']([^"\']+)["\']', re.IGNORECASE)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\+?\d[\d\s().-]{8,}\d")
SCRIPT_STYLE_RE = re.compile(r"<(script|style|noscript)\b.*?</\1>", re.IGNORECASE | re.DOTALL)
COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
HEAD_RE = re.compile(r"<head\b.*?</head>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")
SPACE_RE = re.compile(r"\s+")
WORD_RE = re.compile(r"[a-z]{3,}")

STOPWORDS = set(
    """the and for are but not you all can had her was one our out has his how its may new now old see two way who
    did get let put say she too use that with have this will your from they know want been good much some time very
    when come here just like long make many more only over such take than them well were what where which while
    about after again also because before being between both could does doing down each even every into most other
    should still their then there these those through under until upon would""".split()
)

SOCIAL_DOMAINS = (
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "youtube.com", "github.com", "t.me", "whatsapp.com",
)


# ---------- Helpers ----------
def clean_text(fragment: str) -> str:
    """Strip tags, decode entities, collapse whitespace."""
    return SPACE_RE.sub(" ", unescape(TAG_RE.sub(" ", fragment))).strip()


def host_is_public(url: str) -> bool:
    """Reject localhost / private network addresses so the tool can't be used to probe them."""
    host = urlparse(url).hostname
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
    return True


def fetch(url: str):
    if not URL_RE.match(url):
        raise ValueError("Enter a full address that starts with http:// or https://")
    if not host_is_public(url):
        raise ValueError("That address could not be resolved to a public website.")

    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (URL Content Analyzer)"})
    try:
        with urlopen(req, timeout=TIMEOUT) as resp:
            final_url = resp.geturl()
            if not host_is_public(final_url):
                raise ValueError("The page redirected to a non-public address.")
            ctype = resp.headers.get("Content-Type", "")
            if "html" not in ctype and "text" not in ctype:
                raise ValueError(f"This is not an HTML page (content type: {ctype or 'unknown'}).")
            raw = resp.read(MAX_BYTES)
            charset = resp.headers.get_content_charset() or "utf-8"
    except HTTPError as e:
        raise ValueError(f"The site answered with an error: HTTP {e.code}.")
    except URLError as e:
        raise ValueError(f"Could not reach the site: {e.reason}")
    except TimeoutError:
        raise ValueError("The site took too long to respond.")

    return final_url, len(raw), raw.decode(charset, errors="replace")


def analyze(url: str, html: str, size_bytes: int) -> dict:
    # Title
    m = TITLE_RE.search(html)
    title = clean_text(m.group(1)) if m else ""

    # Meta tags (name/content can appear in either order, so match each part separately)
    meta = {}
    for tag in META_TAG_RE.findall(html):
        n, c = META_NAME_RE.search(tag), META_CONTENT_RE.search(tag)
        if n and c:
            meta[n.group(1).lower()] = unescape(c.group(1)).strip()

    # Headings
    headings = [(int(lvl), clean_text(txt)) for lvl, txt in HEADING_RE.findall(html)]
    headings = [(lvl, txt) for lvl, txt in headings if txt]

    # Links
    base_host = urlparse(url).netloc.lower()
    internal, external, social = set(), set(), set()
    for href in LINK_RE.findall(html):
        href = href.strip()
        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        full = urljoin(url, href)
        parsed = urlparse(full)
        if parsed.scheme not in ("http", "https"):
            continue
        host = parsed.netloc.lower()
        if host == base_host:
            internal.add(full)
        else:
            external.add(full)
            if any(host == d or host.endswith("." + d) for d in SOCIAL_DOMAINS):
                social.add(full)

    # Images
    images = IMG_RE.findall(html)
    missing_alt = sum(1 for tag in images if not IMG_ALT_RE.search(tag))

    # Visible text → words
    body = HEAD_RE.sub(" ", COMMENT_RE.sub(" ", SCRIPT_STYLE_RE.sub(" ", html)))
    text = clean_text(body)
    words = WORD_RE.findall(text.lower())
    top_words = Counter(w for w in words if w not in STOPWORDS).most_common(10)
    top_max = top_words[0][1] if top_words else 1

    # Contacts
    emails = sorted(set(EMAIL_RE.findall(text)) | set(EMAIL_RE.findall(html)))
    phones = sorted({p.strip() for p in PHONE_RE.findall(text) if 10 <= len(re.sub(r"\D", "", p)) <= 13})

    word_count = len(text.split())
    return {
        "url": url,
        "title": title,
        "description": meta.get("description", ""),
        "keywords": meta.get("keywords", ""),
        "word_count": word_count,
        "reading_minutes": max(1, round(word_count / 200)) if word_count else 0,
        "size_kb": round(size_bytes / 1024, 1),
        "headings": headings[:30],
        "heading_total": len(headings),
        "internal_count": len(internal),
        "external_count": len(external),
        "external_links": sorted(external)[:20],
        "social": sorted(social),
        "image_count": len(images),
        "missing_alt": missing_alt,
        "top_words": [(w, n, round(n / top_max * 100)) for w, n in top_words],
        "emails": emails[:20],
        "phones": phones[:20],
    }


# ---------- Routes ----------
ALLOWED_ORIGINS = {"http://127.0.0.1:5500", "http://localhost:5500"}  # Live Server


@app.after_request
def add_cors(resp):
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    return resp


@app.route("/analyze", methods=["POST", "OPTIONS"])
def analyze_api():
    if request.method=="OPTIONS":
        return "", 204
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()
    try:
        final_url, size, html = fetch(url)
        return jsonify(analyze(final_url, html, size))
    except ValueError as e:
        return jsonify(error=str(e)), 400


if __name__ == "__main__":
    app.run(debug=True)
