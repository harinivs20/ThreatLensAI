"""
train_url_model.py — Train Random Forest on PhishTank + synthetic safe URLs
Run: python train_url_model.py
"""
import os, re, math, pickle, random, string
import numpy as np
import pandas as pd
from sklearn.ensemble        import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics         import accuracy_score, classification_report, confusion_matrix

os.makedirs("models", exist_ok=True)

SUSPICIOUS_KEYWORDS = [
    "login","verify","secure","update","account","banking","confirm",
    "suspend","alert","urgent","password","signin","webscr","ebayisapi",
    "paypal","support","service","validate","credential","recover",
]

def _entropy(text):
    if not text: return 0.0
    freq = {}
    for c in text: freq[c] = freq.get(c,0)+1
    n = len(text)
    return -sum((v/n)*math.log2(v/n) for v in freq.values())

def extract_features(url):
    try:
        url = str(url).strip()
        if not url.startswith("http"):
            url = "http://" + url

        # Parse manually (no tldextract needed)
        scheme = "https" if url.startswith("https") else "http"
        rest   = url.split("://",1)[1] if "://" in url else url
        netloc = rest.split("/")[0]
        path   = "/" + "/".join(rest.split("/")[1:]) if "/" in rest else ""

        # Domain extraction
        ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        uses_ip = 1 if ip_re.match(netloc.split(":")[0]) else 0

        parts = netloc.split(".")
        domain = parts[-2] if len(parts) >= 2 else netloc
        suffix = parts[-1] if len(parts) >= 1 else ""
        subdomain_parts = parts[:-2] if len(parts) > 2 else []
        subdomain_count = len(subdomain_parts)

        url_lower = url.lower()
        keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

        # Free/suspicious TLDs
        sus_tlds = {"tk","ml","ga","cf","gq","xyz","click","sbs","top",
                    "online","site","fun","icu","pw","cc","buzz","vip"}
        sus_tld = 1 if suffix.lower() in sus_tlds else 0

        # High-entropy random-looking domains
        dom_entropy = round(_entropy(domain), 4)

        # Domain has digits mixed with letters (e.g. paypa1, amaz0n)
        digit_mix = 1 if (re.search(r'\d', domain) and re.search(r'[a-zA-Z]', domain)) else 0

        # URL length
        url_length = len(url)

        # Dot count
        dot_count = url.count(".")

        # Hyphen count
        hyphen_count = url.count("-")

        # HTTPS
        uses_https = 1 if scheme == "https" else 0

        # @ symbol
        has_at = 1 if "@" in url else 0

        # Path depth
        path_depth = path.count("/")

        # Special char ratio
        special = re.sub(r'[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]', '', url)
        special_ratio = round(len(special) / max(len(url),1), 4)

        # Domain length
        domain_length = len(domain)

        # Has URL shortener
        shorteners = {"bit.ly","tinyurl","goo.gl","ow.ly","t.co","buff.ly","is.gd","short.io"}
        has_shortener = 1 if any(s in url_lower for s in shorteners) else 0

        # Excessive subdomains
        excess_sub = 1 if subdomain_count > 2 else 0

        return [
            url_length, dot_count, hyphen_count, uses_https, uses_ip,
            subdomain_count, domain_length, dom_entropy, keyword_count,
            has_at, path_depth, special_ratio, sus_tld, digit_mix,
            has_shortener, excess_sub
        ]
    except:
        return [0]*16

FEATURE_NAMES = [
    "url_length","dot_count","hyphen_count","uses_https","uses_ip",
    "subdomain_count","domain_length","domain_entropy","keyword_count",
    "has_at","path_depth","special_ratio","sus_tld","digit_mix",
    "has_shortener","excess_subdomain"
]

# ── Load PhishTank phishing URLs ───────────────────────────────────────────────
print("Loading PhishTank dataset...")
df = pd.read_csv("data/verified_online.csv")
phishing_urls = df["url"].dropna().tolist()
print(f"  Phishing URLs loaded: {len(phishing_urls)}")

# ── Generate realistic safe URLs ──────────────────────────────────────────────
print("Generating safe URLs...")
safe_domains = [
    "google.com","youtube.com","facebook.com","github.com","stackoverflow.com",
    "microsoft.com","apple.com","amazon.com","wikipedia.org","twitter.com",
    "linkedin.com","reddit.com","netflix.com","spotify.com","adobe.com",
    "dropbox.com","zoom.us","slack.com","atlassian.com","cloudflare.com",
    "python.org","nodejs.org","reactjs.org","fastapi.tiangolo.com","docs.python.org",
    "developer.mozilla.org","w3schools.com","geeksforgeeks.org","medium.com","dev.to",
    "bbc.com","cnn.com","reuters.com","nytimes.com","theguardian.com",
    "sbi.co.in","hdfcbank.com","icicibank.com","irctc.co.in","nic.in",
]
paths = [
    "/", "/about", "/contact", "/products", "/services", "/blog",
    "/login", "/search?q=python", "/docs/api", "/help/faq",
    "/news/latest", "/account/settings", "/profile", "/dashboard",
]

safe_urls = []
random.seed(42)
target = len(phishing_urls)  # balance classes
while len(safe_urls) < target:
    domain = random.choice(safe_domains)
    path   = random.choice(paths)
    scheme = "https"
    safe_urls.append(f"{scheme}://{domain}{path}")

print(f"  Safe URLs generated: {len(safe_urls)}")

# ── Build features ─────────────────────────────────────────────────────────────
print("Extracting features from phishing URLs...")
X_phish = []
for i, url in enumerate(phishing_urls):
    X_phish.append(extract_features(url))
    if (i+1) % 10000 == 0:
        print(f"  {i+1}/{len(phishing_urls)} done...")

print("Extracting features from safe URLs...")
X_safe = [extract_features(u) for u in safe_urls]

X = np.array(X_phish + X_safe, dtype=float)
y = np.array([1]*len(X_phish) + [0]*len(X_safe))

print(f"\nTotal samples: {len(X)} | Features per URL: {X.shape[1]}")
print(f"Phishing: {y.sum()} | Safe: {(y==0).sum()}")

# ── Train / Test split ────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\nTrain: {len(X_train)} | Test: {len(X_test)}")

# ── Train Random Forest ───────────────────────────────────────────────────────
print("\nTraining Random Forest (200 trees)...")
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)
model.fit(X_train, y_train)

# ── Evaluate ──────────────────────────────────────────────────────────────────
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)

print(f"\n{'='*50}")
print(f"  ACCURACY: {acc*100:.2f}%")
print(f"{'='*50}")
print(classification_report(y_test, y_pred, target_names=["Safe","Phishing"]))
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Feature importance
print("\nTop 5 Most Important Features:")
importances = model.feature_importances_
idx = np.argsort(importances)[::-1]
for i in range(5):
    print(f"  {i+1}. {FEATURE_NAMES[idx[i]]}: {importances[idx[i]]:.4f}")

# ── Save model ────────────────────────────────────────────────────────────────
payload = {
    "model":         model,
    "feature_names": FEATURE_NAMES,
    "accuracy":      acc,
    "extract_fn":    extract_features,
}
with open("models/url_model.pkl","wb") as f:
    pickle.dump(payload, f)

print(f"\n✅ Model saved to models/url_model.pkl")
print(f"   Accuracy: {acc*100:.2f}%")
print(f"\nNext step: uvicorn main:app --reload --port 8000")
