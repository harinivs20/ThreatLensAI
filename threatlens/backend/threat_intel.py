"""
threat_intel.py — Live threat intelligence lookup from public APIs.

When a scan doesn't match any local campaign, this module queries:
1. PhishTank API   — checks if URL is known phishing
2. URLhaus API     — abuse.ch malware/phishing URL database  
3. OpenPhish feed  — fresh phishing URL list

If a match is found online, a new campaign entry is created and
saved to the local database for future use.
"""
import os, re, json, math, uuid, hashlib
import requests
from datetime import datetime

# Timeout for all external API calls
API_TIMEOUT = 6  # seconds

# ── In-memory cache to avoid repeated API calls for same URL ──────────────────
_cache: dict = {}

def _cache_key(url: str) -> str:
    return hashlib.md5(url.encode()).hexdigest()


def lookup_url_online(url: str) -> dict:
    """
    Query public threat intel APIs for a URL.
    Returns a campaign-like dict if found, empty dict if clean/unknown.
    """
    key = _cache_key(url)
    if key in _cache:
        return _cache[key]

    result = {}

    # Try each source — stop on first hit
    result = (_lookup_urlhaus(url) or
              _lookup_phishtank(url) or
              _lookup_openphish(url) or
              {})

    _cache[key] = result
    return result


def _lookup_urlhaus(url: str) -> dict:
    """
    Query URLhaus (abuse.ch) — free public API, no key needed.
    Docs: https://urlhaus-api.abuse.ch/
    """
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=API_TIMEOUT
        )
        if resp.status_code != 200:
            return {}

        data = resp.json()
        if data.get("query_status") != "is_listed":
            return {}

        # Extract tags and threat info
        tags = data.get("tags") or []
        threat = data.get("threat", "malware")
        host = data.get("host", "")
        date_added = data.get("date_added", "")[:10] if data.get("date_added") else ""
        reporter = data.get("reporter", "Unknown")
        payloads = data.get("payloads") or []
        payload_types = list(set(p.get("file_type","") for p in payloads if p.get("file_type")))

        # Build campaign name from threat type and tags
        tag_str = ", ".join(tags[:3]) if tags else threat
        name = f"URLhaus — {threat.title()} Campaign ({tag_str})"

        # Try to determine target sector from tags
        org_types = _infer_org_types_from_tags(tags, threat)

        return {
            "id":          f"urlhaus-{_cache_key(url)[:8]}",
            "name":        name,
            "description": (
                f"Detected by URLhaus (abuse.ch). Threat type: {threat}. "
                f"Host: {host}. "
                + (f"Tags: {', '.join(tags)}. " if tags else "")
                + (f"Payload types: {', '.join(payload_types)}. " if payload_types else "")
                + f"Reported by: {reporter}."
            ),
            "org_types":   org_types,
            "first_seen":  date_added,
            "last_seen":   datetime.now().strftime("%Y-%m-%d"),
            "region":      "Unknown (Global)",
            "total_orgs":  len(org_types),
            "template":    threat,
            "source":      "URLhaus / abuse.ch",
            "source_url":  data.get("urlhaus_reference", "https://urlhaus.abuse.ch"),
            "similarity":  92.0,
            "online":      True,
        }

    except Exception as e:
        print(f"[ThreatIntel] URLhaus error: {e}")
        return {}


def _lookup_phishtank(url: str) -> dict:
    """
    Query PhishTank — free public API.
    Returns hit if URL is in their verified phishing database.
    """
    try:
        resp = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={
                "url":    url,
                "format": "json",
            },
            headers={"User-Agent": "ThreatLens-AI/2.0"},
            timeout=API_TIMEOUT
        )
        if resp.status_code != 200:
            return {}

        data = resp.json()
        results = data.get("results", {})

        if not results.get("in_database"):
            return {}
        if not results.get("valid"):
            return {}

        verified    = results.get("verified", False)
        verified_at = results.get("verified_at", "")[:10] if results.get("verified_at") else ""
        phish_id    = results.get("phish_id", "")
        phish_detail_url = results.get("phish_detail_page", "")

        # Try to detect target from URL
        target = _detect_brand_from_url(url)
        name   = f"PhishTank — {target} Phishing Campaign" if target else "PhishTank — Verified Phishing Campaign"

        org_types = {"Financial Institutions": 3, "General Public": 5}
        if target:
            if target.lower() in ["sbi","hdfc","icici","paytm","bank"]:
                org_types = {"Banks / Financial Services": 6, "General Public": 4}
            elif target.lower() in ["amazon","flipkart","meesho"]:
                org_types = {"E-commerce Platforms": 5, "General Public": 6}
            elif target.lower() in ["google","microsoft","facebook","apple"]:
                org_types = {"IT / Tech Companies": 4, "Educational Institutions": 4, "General Public": 5}

        return {
            "id":          f"phishtank-{phish_id}" if phish_id else f"phishtank-{_cache_key(url)[:8]}",
            "name":        name,
            "description": (
                f"Verified phishing URL in PhishTank database"
                + (f" (ID: {phish_id})" if phish_id else "")
                + (f". Verified at: {verified_at}" if verified_at else "")
                + (f". Targets: {target}" if target else "")
                + "."
            ),
            "org_types":   org_types,
            "first_seen":  verified_at or datetime.now().strftime("%Y-%m-%d"),
            "last_seen":   datetime.now().strftime("%Y-%m-%d"),
            "region":      "Unknown (Global)",
            "total_orgs":  sum(org_types.values()),
            "template":    f"{target.lower()}-clone" if target else "phishing-clone",
            "source":      "PhishTank",
            "source_url":  phish_detail_url or "https://www.phishtank.com",
            "similarity":  95.0,
            "online":      True,
        }

    except Exception as e:
        print(f"[ThreatIntel] PhishTank error: {e}")
        return {}


def _lookup_openphish(url: str) -> dict:
    """
    Check against OpenPhish community feed (cached locally, refreshed hourly).
    OpenPhish provides a plain text feed of active phishing URLs.
    """
    try:
        feed = _get_openphish_feed()
        if not feed:
            return {}

        # Check if URL or domain appears in feed
        domain = _extract_domain(url)
        for feed_url in feed:
            if url in feed_url or (domain and domain in feed_url):
                target = _detect_brand_from_url(feed_url)
                name   = f"OpenPhish — {target} Active Campaign" if target else "OpenPhish — Active Phishing Campaign"
                return {
                    "id":          f"openphish-{_cache_key(url)[:8]}",
                    "name":        name,
                    "description": (
                        f"URL found in OpenPhish community phishing feed. "
                        f"This is an active phishing URL verified by the OpenPhish platform"
                        + (f" targeting {target}" if target else "")
                        + "."
                    ),
                    "org_types":   {"General Public": 8, "Educational Institutions": 3, "Banks / Financial Services": 2},
                    "first_seen":  datetime.now().strftime("%Y-%m-%d"),
                    "last_seen":   datetime.now().strftime("%Y-%m-%d"),
                    "region":      "Unknown (Global)",
                    "total_orgs":  13,
                    "template":    f"{target.lower()}-clone" if target else "active-phishing",
                    "source":      "OpenPhish",
                    "source_url":  "https://openphish.com",
                    "similarity":  88.0,
                    "online":      True,
                }
        return {}

    except Exception as e:
        print(f"[ThreatIntel] OpenPhish error: {e}")
        return {}


# ── Feed cache ─────────────────────────────────────────────────────────────────
_openphish_cache = {"data": [], "fetched_at": None}

def _get_openphish_feed() -> list:
    """Fetch OpenPhish community feed, cached for 1 hour."""
    now = datetime.now()
    if (_openphish_cache["fetched_at"] and
        (now - _openphish_cache["fetched_at"]).seconds < 3600 and
        _openphish_cache["data"]):
        return _openphish_cache["data"]

    try:
        resp = requests.get(
            "https://openphish.com/feed.txt",
            timeout=API_TIMEOUT,
            headers={"User-Agent": "ThreatLens-AI/2.0"}
        )
        if resp.status_code == 200:
            urls = [l.strip() for l in resp.text.splitlines() if l.strip()]
            _openphish_cache["data"]       = urls
            _openphish_cache["fetched_at"] = now
            print(f"[ThreatIntel] OpenPhish feed loaded: {len(urls)} URLs")
            return urls
    except Exception as e:
        print(f"[ThreatIntel] OpenPhish feed fetch failed: {e}")
    return []


# ── Helpers ────────────────────────────────────────────────────────────────────
BRAND_PATTERNS = {
    "paypal":    ["paypal","paypai","paypa1","pp-"],
    "amazon":    ["amazon","amaz0n","amzon","amzn"],
    "google":    ["google","g00gle","googl","gmail"],
    "microsoft": ["microsoft","micros0ft","microsft","office365","outlook"],
    "apple":     ["apple","app1e","icloud","itunes"],
    "facebook":  ["facebook","faceb00k","fb-","meta-"],
    "sbi":       ["sbi","sbibank","sbionline","onlinesbi"],
    "hdfc":      ["hdfc","hdfcbank","hdfc-"],
    "icici":     ["icici","icicib","icicibank"],
    "irctc":     ["irctc","indianrailways","irail"],
    "flipkart":  ["flipkart","fl1pkart","fllpkart"],
    "netflix":   ["netflix","netfl1x","nettlix"],
    "whatsapp":  ["whatsapp","whats-app","watsapp"],
    "instagram": ["instagram","1nstagram","instagr"],
    "twitter":   ["twitter","twiter","tw1tter"],
}

def _detect_brand_from_url(url: str) -> str:
    url_lower = url.lower()
    for brand, patterns in BRAND_PATTERNS.items():
        if any(p in url_lower for p in patterns):
            return brand.title()
    return ""

def _extract_domain(url: str) -> str:
    try:
        if "://" in url:
            url = url.split("://", 1)[1]
        return url.split("/")[0].split(":")[0]
    except:
        return ""

def _infer_org_types_from_tags(tags: list, threat: str) -> dict:
    tags_lower = [t.lower() for t in tags]
    threat_lower = threat.lower()

    if any(t in tags_lower+[threat_lower] for t in ["banker","banking","bank","trojan"]):
        return {"Banks / Financial Services": 6, "General Public": 4, "E-commerce Platforms": 2}
    elif any(t in tags_lower+[threat_lower] for t in ["phishing","credential","login"]):
        return {"General Public": 8, "Educational Institutions": 3, "Banks / Financial Services": 3}
    elif any(t in tags_lower for t in ["emotet","trickbot","qakbot","ransomware"]):
        return {"IT / Tech Companies": 5, "Healthcare Organisations": 3, "Banks / Financial Services": 4}
    elif any(t in tags_lower for t in ["rat","remote","stealer"]):
        return {"IT / Tech Companies": 6, "Educational Institutions": 4, "General Public": 3}
    else:
        return {"General Public": 7, "Educational Institutions": 2, "Banks / Financial Services": 2}


# ── Save online campaign to local DB for future use ───────────────────────────
def save_online_campaign_to_db(campaign: dict):
    """Persist a discovered online campaign into the local campaigns table."""
    try:
        from database import get_conn, init_db
        conn = get_conn()
        # Create campaigns table if not exists
        conn.execute("""
            CREATE TABLE IF NOT EXISTS discovered_campaigns (
                id          TEXT PRIMARY KEY,
                name        TEXT,
                description TEXT,
                org_types   TEXT,
                first_seen  TEXT,
                last_seen   TEXT,
                region      TEXT,
                total_orgs  INTEGER,
                template    TEXT,
                source      TEXT,
                source_url  TEXT,
                created_at  TEXT
            )
        """)
        conn.execute("""
            INSERT OR IGNORE INTO discovered_campaigns
            (id,name,description,org_types,first_seen,last_seen,region,
             total_orgs,template,source,source_url,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            campaign.get("id",""),
            campaign.get("name",""),
            campaign.get("description",""),
            json.dumps(campaign.get("org_types",{})),
            campaign.get("first_seen",""),
            campaign.get("last_seen",""),
            campaign.get("region",""),
            campaign.get("total_orgs",0),
            campaign.get("template",""),
            campaign.get("source",""),
            campaign.get("source_url",""),
            datetime.now().isoformat(),
        ))
        conn.commit()
        conn.close()
        print(f"[ThreatIntel] Saved online campaign to DB: {campaign.get('name')}")
    except Exception as e:
        print(f"[ThreatIntel] Could not save online campaign: {e}")


def get_discovered_campaigns(limit=50) -> list:
    """Return campaigns discovered online and saved to local DB."""
    try:
        from database import get_conn
        conn = get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS discovered_campaigns (
                id TEXT PRIMARY KEY, name TEXT, description TEXT,
                org_types TEXT, first_seen TEXT, last_seen TEXT,
                region TEXT, total_orgs INTEGER, template TEXT,
                source TEXT, source_url TEXT, created_at TEXT
            )
        """)
        rows = conn.execute("""
            SELECT * FROM discovered_campaigns ORDER BY created_at DESC LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        result = []
        for r in rows:
            d = dict(r)
            d["org_types"] = json.loads(d["org_types"]) if d["org_types"] else {}
            result.append(d)
        return result
    except Exception as e:
        print(f"[ThreatIntel] get_discovered_campaigns error: {e}")
        return []
