"""
train_models.py — Train XGBoost (email) and Random Forest (URL) classifiers.

Run once before starting the server:
    python train_models.py

Requires:
    data/phishing_email.csv   — Kaggle phishing email dataset
    data/verified_online.csv  — PhishTank URL dataset (optional)

Output:
    models/email_model.pkl
    models/url_model.pkl
"""

import os
import pickle
import pandas as pd
import numpy as np
from sklearn.ensemble         import RandomForestClassifier
from sklearn.model_selection  import train_test_split
from sklearn.metrics          import classification_report, accuracy_score
from sklearn.feature_extraction.text import TfidfVectorizer
from xgboost import XGBClassifier

from email_features import extract_email_features
from url_features   import extract_url_features

os.makedirs("models", exist_ok=True)
os.makedirs("data",   exist_ok=True)


# ── 1. Train Email Model (XGBoost + TF-IDF) ──────────────────────────────────
def train_email_model():
    csv_path = "data/phishing_email.csv"
    if not os.path.exists(csv_path):
        print(f"[SKIP] Email dataset not found at {csv_path}")
        print("       Download from: https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset")
        return

    print("\n[EMAIL MODEL] Loading dataset...")
    df = pd.read_csv(csv_path)

    # Handle common column name variants
    text_col  = next((c for c in df.columns if 'text'  in c.lower()), None)
    label_col = next((c for c in df.columns if 'label' in c.lower() or 'type' in c.lower()), None)

    if not text_col or not label_col:
        print(f"[ERROR] Could not find text/label columns. Found: {df.columns.tolist()}")
        return

    df = df[[text_col, label_col]].dropna()
    df.columns = ['text', 'label']

    # Normalise labels to 0/1
    df['label'] = df['label'].apply(
        lambda x: 1 if str(x).strip().lower() in ['1', 'phishing', 'spam', 'malicious'] else 0
    )

    print(f"[EMAIL MODEL] Dataset: {len(df)} rows | Phishing: {df['label'].sum()} | Safe: {(df['label']==0).sum()}")

    # TF-IDF features
    print("[EMAIL MODEL] Extracting TF-IDF features...")
    tfidf = TfidfVectorizer(max_features=5000, stop_words='english', ngram_range=(1, 2))
    X = tfidf.fit_transform(df['text']).toarray()
    y = df['label'].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("[EMAIL MODEL] Training XGBoost...")
    model = XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1,
                          use_label_encoder=False, eval_metric='logloss', random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"[EMAIL MODEL] Accuracy: {acc*100:.2f}%")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))

    # Save model + vectorizer together
    with open("models/email_model.pkl", "wb") as f:
        pickle.dump({"model": model, "tfidf": tfidf, "accuracy": acc}, f)
    print("[EMAIL MODEL] Saved to models/email_model.pkl ✅")


# ── 2. Train URL Model (Random Forest + structural features) ──────────────────
def train_url_model():
    csv_path = "data/verified_online.csv"
    if not os.path.exists(csv_path):
        print(f"\n[SKIP] URL dataset not found at {csv_path}")
        print("       Download from: https://www.phishtank.com/developer_info.php")

        # Generate a small synthetic dataset for demo purposes
        print("[URL MODEL] Generating synthetic demo dataset (500 samples)...")
        import random, string

        tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.club', '.info']
        safe_domains = ['google.com', 'github.com', 'microsoft.com', 'amazon.com', 'stackoverflow.com']

        rows = []
        # Phishing URLs
        for _ in range(250):
            dom = ''.join(random.choices(string.ascii_lowercase, k=random.randint(8, 18)))
            tld = random.choice(tlds)
            kw  = random.choice(['login', 'verify', 'secure', 'account', 'update'])
            url = f"http://{dom}{tld}/{kw}?id={random.randint(100,999)}"
            rows.append({'url': url, 'label': 1})
        # Safe URLs
        for _ in range(250):
            dom = random.choice(safe_domains)
            path = ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 8)))
            url = f"https://{dom}/{path}"
            rows.append({'url': url, 'label': 0})

        df = pd.DataFrame(rows)
        df.to_csv("data/synthetic_urls.csv", index=False)
        csv_path = "data/synthetic_urls.csv"
        print(f"[URL MODEL] Synthetic dataset saved to {csv_path}")

    print("\n[URL MODEL] Loading dataset...")
    df = pd.read_csv(csv_path)

    # Handle PhishTank column format
    url_col   = next((c for c in df.columns if 'url'   in c.lower()), None)
    label_col = next((c for c in df.columns if 'label' in c.lower() or 'phish' in c.lower()), None)

    if not url_col:
        print(f"[ERROR] Could not find URL column. Found: {df.columns.tolist()}")
        return

    df = df[[url_col] + ([label_col] if label_col else [])].dropna()
    if label_col:
        df.columns = ['url', 'label']
        df['label'] = df['label'].apply(
            lambda x: 1 if str(x).strip() in ['1', 'y', 'yes', 'phishing', 'malicious'] else 0
        )
    else:
        # PhishTank — all entries are phishing
        df.columns = ['url']
        df['label'] = 1

    print(f"[URL MODEL] Dataset: {len(df)} rows | Phishing: {df['label'].sum()} | Safe: {(df['label']==0).sum()}")

    # Extract structural features
    print("[URL MODEL] Extracting URL features (this may take a minute)...")
    features_list = []
    for url in df['url']:
        try:
            f = extract_url_features(str(url))
            features_list.append(list(f.values()))
        except:
            features_list.append([0] * 12)

    feature_names = list(extract_url_features("http://example.com").keys())
    X = np.array(features_list)
    y = df['label'].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("[URL MODEL] Training Random Forest...")
    model = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"[URL MODEL] Accuracy: {acc*100:.2f}%")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))

    with open("models/url_model.pkl", "wb") as f:
        pickle.dump({"model": model, "feature_names": feature_names, "accuracy": acc}, f)
    print("[URL MODEL] Saved to models/url_model.pkl ✅")


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  ThreatLens AI — Model Training Script")
    print("=" * 60)
    train_email_model()
    train_url_model()
    print("\n✅ Training complete. Start the server with:")
    print("   uvicorn main:app --reload --port 8000")
