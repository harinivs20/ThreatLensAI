"""
email_features.py — Email phishing detection using trained ML model + rule-based fallback.
"""
import os, re, pickle
import numpy as np

URGENCY_WORDS = ["immediately","urgent","suspended","verify","confirm","expire",
    "unusual","unauthorized","breach","click here","action required","limited time",
    "within 24","account locked","security alert","lose access","terminate"]
FEAR_WORDS    = ["terminated","suspended","blocked","unauthorized","breach","detected","failure"]
CRED_WORDS    = ["password","card number","bank account","ssn","date of birth",
    "credit card","debit card","pin","otp","cvv"]
BRAND_WORDS   = ["paypal","amazon","apple","google","microsoft","netflix","sbi","hdfc",
    "icici","facebook","instagram","twitter","linkedin"]
URGENCY_PHRASES = ["immediately","urgent","act now","within 24 hours","expire","suspended",
    "verify now","confirm now","limited time","asap","action required","account locked",
    "unusual activity","click here","click immediately","lose access"]
FEAR_PHRASES    = ["will be terminated","lose access","permanently disabled",
    "unauthorized access","security breach","suspicious activity","failure to"]
CREDENTIAL_PHRASES = ["enter your password","provide your","update your details",
    "verify your identity","confirm your account","enter your credit","bank account"]

_EMAIL_MODEL = None

def _load_email_model():
    global _EMAIL_MODEL
    if _EMAIL_MODEL is None:
        path = os.path.join(os.path.dirname(__file__), "models", "email_model.pkl")
        if os.path.exists(path):
            with open(path,"rb") as f:
                _EMAIL_MODEL = pickle.load(f)
            print(f"[ThreatLens] Email model loaded — accuracy {_EMAIL_MODEL['accuracy']*100:.1f}%")
        else:
            print("[ThreatLens] No email model — using rule-based scoring.")
    return _EMAIL_MODEL

def _handcrafted_features(text):
    tl = text.lower()
    urls = re.findall(r'http\S+', tl)
    sus_urls = sum(1 for u in urls if any(s in u for s in
        ["bit.ly","tiny","tk","xyz","click","sbs"]) or not u.startswith("https"))
    return np.array([[
        sum(1 for w in URGENCY_WORDS if w in tl),
        sum(1 for w in FEAR_WORDS    if w in tl),
        sum(1 for w in CRED_WORDS    if w in tl),
        sum(1 for w in BRAND_WORDS   if w in tl),
        len(urls), sus_urls,
        1 if re.search(r'\b(dear customer|dear user|dear member|dear valued)\b', tl) else 0,
        len(re.findall(r'\b[A-Z]{3,}\b', text)),
        text.count("!"),
        len(text.split()),
    ]], dtype=float)

def extract_email_features(text: str) -> dict:
    tl = text.lower()
    urls = re.findall(r'http\S+', tl)
    return {
        "urgency_count":      sum(1 for p in URGENCY_PHRASES    if p in tl),
        "fear_count":         sum(1 for p in FEAR_PHRASES       if p in tl),
        "credential_count":   sum(1 for p in CREDENTIAL_PHRASES if p in tl),
        "brand_count":        sum(1 for b in BRAND_WORDS        if b in tl),
        "url_count":          len(urls),
        "suspicious_urls":    sum(1 for u in urls if any(s in u for s in
                                  ["bit.ly","tinyurl","tk","xyz","click"]) or not u.startswith("https")),
        "generic_salutation": 1 if re.search(
                                  r'\b(dear customer|dear user|dear member|dear valued)\b', tl) else 0,
        "caps_words":         len(re.findall(r'\b[A-Z]{3,}\b', text)),
        "exclamation_count":  text.count("!"),
        "word_count":         len(text.split()),
    }

def score_email_features(features: dict) -> dict:
    # Try ML model first — we need raw text, so rebuild from features heuristically
    # The actual ML scoring is done in main.py via score_email_text()
    sender_risk = 0
    if features["generic_salutation"]: sender_risk += 40
    if features["brand_count"] > 0:    sender_risk += 30
    if features["suspicious_urls"] > 0: sender_risk += 30
    sender_risk = min(sender_risk, 100)

    lang_risk = 0
    lang_risk += min(features["urgency_count"] * 15, 45)
    lang_risk += min(features["fear_count"]    * 20, 40)
    lang_risk += min(features["caps_words"]    *  5, 15)
    lang_risk = min(lang_risk, 100)

    cred_risk  = min(features["credential_count"] * 25, 100)
    link_risk  = 0
    if features["suspicious_urls"] > 0: link_risk += 50
    if features["url_count"] > 3:       link_risk += 30
    link_risk = min(link_risk, 100)

    urgency_score = min(
        features["urgency_count"] * 2 + features["fear_count"] * 3 +
        (1 if features["exclamation_count"] > 2 else 0), 10)

    overall = int(sender_risk*0.25 + lang_risk*0.30 + cred_risk*0.25 + link_risk*0.20)

    def grade(s):
        return "F" if s>=80 else "D" if s>=60 else "C" if s>=40 else "B" if s>=20 else "A"

    return {
        "sender_authenticity":   {"score": sender_risk, "grade": grade(sender_risk)},
        "language_manipulation": {"score": lang_risk,   "grade": grade(lang_risk)},
        "credential_risk":       {"score": cred_risk,   "grade": grade(cred_risk)},
        "link_safety":           {"score": link_risk,   "grade": grade(link_risk)},
        "urgency_score":         urgency_score,
        "overall_risk":          overall,
    }

def score_email_text_ml(text: str) -> int:
    """Use trained ML model to get phishing probability from raw email text."""
    mdl = _load_email_model()
    if not mdl:
        return -1  # signal fallback
    try:
        hf  = _handcrafted_features(text)
        tf  = mdl["tfidf"].transform([text]).toarray()
        xv  = np.hstack([hf, tf])
        prob = mdl["model"].predict_proba(xv)[0][1]
        return int(prob * 100)
    except Exception as e:
        print(f"[EMAIL ML] Error: {e}")
        return -1
