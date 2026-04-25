"""
url_features.py — URL feature extraction + hybrid ML + rule-based scoring.
"""
import os, re, math, pickle
import numpy as np

SUSPICIOUS_KEYWORDS = ["login","verify","secure","update","account","banking","confirm",
    "suspend","alert","urgent","password","signin","webscr","paypal","support",
    "service","validate","credential","recover"]
SUS_TLDS   = {"tk","ml","ga","cf","gq","xyz","click","sbs","top","online","site",
              "fun","icu","pw","cc","buzz","vip","ga","monster","bar","cyou"}
SHORTENERS = {"bit.ly","tinyurl","goo.gl","ow.ly","t.co","buff.ly","is.gd","short.io"}
TRUSTED_DOMAINS = {"google","youtube","facebook","github","microsoft","apple","amazon",
    "wikipedia","twitter","linkedin","reddit","netflix","spotify","stackoverflow",
    "python","nodejs","mozilla","cloudflare","github","gitlab","bbc","cnn","reuters",
    "sbi","hdfc","icici","irctc","nasa","who","mit","stanford","dropbox","zoom","slack"}

_MODEL = None

def _load_model():
    global _MODEL
    if _MODEL is None:
        path = os.path.join(os.path.dirname(__file__), "models", "url_model.pkl")
        if os.path.exists(path):
            with open(path, "rb") as f:
                _MODEL = pickle.load(f)
            print(f"[ThreatLens] URL model loaded — accuracy {_MODEL['accuracy']*100:.1f}%")
        else:
            print("[ThreatLens] No trained model — using rule-based scoring.")
    return _MODEL

def _entropy(text):
    if not text: return 0.0
    freq = {}
    for c in text: freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((v/n)*math.log2(v/n) for v in freq.values())

def extract_url_features(url: str) -> dict:
    try:
        url = str(url).strip()
        if not url.startswith("http"): url = "http://" + url
        scheme = "https" if url.startswith("https") else "http"
        rest   = url.split("://",1)[1] if "://" in url else url
        netloc = rest.split("/")[0]
        path   = "/" + "/".join(rest.split("/")[1:]) if "/" in rest else ""
        ip_re  = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        uses_ip = 1 if ip_re.match(netloc.split(":")[0]) else 0
        parts   = netloc.split(".")
        domain  = parts[-2] if len(parts)>=2 else netloc
        suffix  = parts[-1] if parts else ""
        subdomain_count = len(parts)-2 if len(parts)>2 else 0
        url_lower = url.lower()
        special = re.sub(r'[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]','',url)
        return {
            "url_length":       len(url),
            "dot_count":        url.count("."),
            "hyphen_count":     url.count("-"),
            "uses_https":       1 if scheme=="https" else 0,
            "uses_ip":          uses_ip,
            "subdomain_count":  subdomain_count,
            "domain_length":    len(domain),
            "domain_entropy":   round(_entropy(domain),4),
            "keyword_count":    sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower),
            "has_at":           1 if "@" in url else 0,
            "path_depth":       path.count("/"),
            "special_ratio":    round(len(special)/max(len(url),1),4),
            "sus_tld":          1 if suffix.lower() in SUS_TLDS else 0,
            "digit_mix":        1 if (re.search(r'\d',domain) and re.search(r'[a-zA-Z]',domain)) else 0,
            "has_shortener":    1 if any(s in url_lower for s in SHORTENERS) else 0,
            "excess_subdomain": 1 if subdomain_count>2 else 0,
            "_domain":          domain.lower(),
            "_suffix":          suffix.lower(),
        }
    except:
        return {k:0 for k in ["url_length","dot_count","hyphen_count","uses_https","uses_ip",
            "subdomain_count","domain_length","domain_entropy","keyword_count","has_at",
            "path_depth","special_ratio","sus_tld","digit_mix","has_shortener","excess_subdomain",
            "_domain","_suffix"]}

def score_url_features(features: dict) -> dict:
    domain = features.get("_domain","")
    suffix = features.get("_suffix","")

    # ── Hard SAFE rules — trusted domain, HTTPS, no tricks ────────────────
    is_trusted = domain in TRUSTED_DOMAINS and suffix in {"com","org","net","gov","edu","in","io","co"}
    is_clean   = (features["uses_https"]==1 and features["uses_ip"]==0 and
                  features["sus_tld"]==0 and features["digit_mix"]==0 and
                  features["has_at"]==0 and features["has_shortener"]==0 and
                  features["keyword_count"]==0 and features["excess_subdomain"]==0)

    if is_trusted and is_clean:
        overall_risk = 2  # clearly safe
    # ── Hard PHISHING rules ────────────────────────────────────────────────
    elif (features["uses_ip"]==1 or features["has_at"]==1 or
          (features["sus_tld"]==1 and features["digit_mix"]==1) or
          (features["sus_tld"]==1 and features["keyword_count"]>=2)):
        overall_risk = 95  # clearly phishing
    else:
        # ── ML model for ambiguous cases ───────────────────────────────────
        mdl = _load_model()
        if mdl:
            feat_names = mdl["feature_names"]
            feat_vec   = np.array([[features.get(n,0) for n in feat_names]])
            prob       = mdl["model"].predict_proba(feat_vec)[0][1]
            ml_risk    = int(prob * 100)

            # Blend: if clean signals say safe, cap ML risk
            if is_clean:
                overall_risk = min(ml_risk, 30)
            elif features["sus_tld"]==1 or features["digit_mix"]==1:
                overall_risk = max(ml_risk, 60)
            else:
                overall_risk = ml_risk
        else:
            overall_risk = _rule_risk(features)

    # ── Dimension scores for report card ──────────────────────────────────
    domain_risk = min(sum([
        40 if features["uses_ip"] else 0,
        25 if features["domain_entropy"]>3.5 else 0,
        15 if features["domain_length"]>20 else 0,
        20 if features["sus_tld"] else 0,
        15 if features["digit_mix"] else 0,
    ]), 100)
    link_risk = min(sum([
        35 if not features["uses_https"] else 0,
        30 if features["has_at"] else 0,
        25 if features["has_shortener"] else 0,
        20 if features["keyword_count"]>=2 else 0,
        15 if features["special_ratio"]>0.1 else 0,
    ]), 100)
    struct_risk = min(sum([
        25 if features["url_length"]>75 else 0,
        20 if features["excess_subdomain"] else 0,
        15 if features["hyphen_count"]>3 else 0,
        10 if features["path_depth"]>4 else 0,
    ]), 100)
    lang_risk = min(features["keyword_count"]*20, 100)

    def grade(s):
        return "F" if s>=80 else "D" if s>=60 else "C" if s>=40 else "B" if s>=20 else "A"

    return {
        "domain_reputation": {"score": domain_risk,  "grade": grade(domain_risk)},
        "link_safety":       {"score": link_risk,    "grade": grade(link_risk)},
        "structure_risk":    {"score": struct_risk,  "grade": grade(struct_risk)},
        "keyword_risk":      {"score": lang_risk,    "grade": grade(lang_risk)},
        "overall_risk":      overall_risk,
    }

def _rule_risk(f):
    dr = min(40*(f["uses_ip"]>0)+25*(f["domain_entropy"]>3.5)+15*(f["domain_length"]>20)+10*(f["dot_count"]>5),100)
    lr = min(35*(not f["uses_https"])+30*(f["has_at"]>0)+20*(f["keyword_count"]>=2)+15*(f["special_ratio"]>0.1),100)
    sr = min(25*(f["url_length"]>75)+20*(f["subdomain_count"]>2)+15*(f["hyphen_count"]>3),100)
    kr = min(f["keyword_count"]*20,100)
    return int(dr*0.35+lr*0.35+sr*0.15+kr*0.15)
