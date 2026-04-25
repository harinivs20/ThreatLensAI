"""
train_email_model.py — Train email phishing classifier.

If you have data/phishing_email.csv (from Kaggle), it uses that.
Otherwise generates realistic synthetic training data.

Run: python train_email_model.py
Output: models/email_model.pkl
"""
import os, pickle, random, re
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer

os.makedirs("models", exist_ok=True)
random.seed(42)
np.random.seed(42)

# ── Synthetic data generators ──────────────────────────────────────────────────
BRANDS   = ["PayPal","Amazon","Apple","Google","Microsoft","Netflix","SBI Bank",
            "HDFC Bank","ICICI Bank","Facebook","Instagram","Twitter","LinkedIn"]
URGENCY  = ["immediately","within 24 hours","right now","URGENT","action required",
            "account suspended","verify now","click here","limited time","expires today"]
FEARS    = ["will be terminated","lose access","unauthorized access",
            "security breach","unusual activity","we detected","failure to respond"]
CREDS    = ["enter your password","provide your details","verify your identity",
            "confirm your account","reset your password","enter your card number",
            "update your information","complete verification"]
SAFE_GREET = ["Hi John","Hello Sarah","Dear Mr. Sharma","Hi team","Hey everyone",
               "Dear Dr. Kumar","Hi Priya","Hello Rajesh"]
SAFE_TOPICS = [
    "Please find attached the monthly report for your review.",
    "The meeting has been rescheduled to Thursday at 3 PM.",
    "Just a reminder about the team lunch tomorrow.",
    "Congratulations on completing the project successfully.",
    "The Q3 results look great — well done to everyone.",
    "Could you please review the attached document and share feedback?",
    "I wanted to follow up on our conversation from last week.",
    "The new policy changes will take effect from next Monday.",
    "Looking forward to seeing everyone at the conference.",
    "Please let me know if you need any assistance.",
]

def gen_phishing():
    brand   = random.choice(BRANDS)
    urgency = random.sample(URGENCY, random.randint(1,3))
    fear    = random.sample(FEARS,   random.randint(0,2))
    cred    = random.sample(CREDS,   random.randint(1,2))
    url     = random.choice(["http://bit.ly/secure","http://tiny.cc/verify",
              f"http://{brand.lower().replace(' ','')}1-secure.tk/login",
              f"http://verify-{brand.lower().replace(' ','-')}.xyz/account"])
    greeting = random.choice(["Dear Customer","Dear Valued Member",
                               "Dear Account Holder","Dear User","To Whom It May Concern"])
    lines = [
        f"From: noreply@{brand.lower().replace(' ','')}support.com",
        f"Subject: {'!!!' if random.random()>0.5 else ''}{random.choice(urgency).upper()}: Your {brand} Account",
        "",
        f"{greeting},",
        "",
        f"We have detected {random.choice(['unusual activity','suspicious login','security issues'])} on your {brand} account.",
        f"You must {random.choice(cred)} {random.choice(urgency)}.",
        " ".join(fear) if fear else f"Your account will be {random.choice(['suspended','locked','terminated'])}.",
        "",
        f"Click here to verify: {url}",
        "",
        f"{'!!! ' * random.randint(1,3)}{'DO NOT IGNORE THIS MESSAGE.' if random.random()>0.4 else ''}",
        "",
        f"- {brand} Security Team",
    ]
    return "\n".join(lines)

def gen_safe():
    greeting = random.choice(SAFE_GREET)
    topic    = random.choice(SAFE_TOPICS)
    extra    = random.choice([
        "Best regards,\nThe Team",
        "Thanks,\nRajesh",
        "Cheers,\nSarah",
        "Kind regards,\nDr. Kumar",
        "Warm regards,\nPriya",
    ])
    domain   = random.choice(["company.com","college.edu","organization.org",
                               "team.net","workplace.in"])
    lines = [
        f"From: {random.choice(['john','priya','rajesh','sarah','kumar'])}@{domain}",
        f"Subject: {random.choice(['FYI','Update','Quick note','Following up','Reminder'])} — {topic[:40]}",
        "",
        f"{greeting},",
        "",
        topic,
        "",
        f"Please feel free to reach out if you have any questions.",
        "",
        extra,
    ]
    return "\n".join(lines)

# ── Build dataset ──────────────────────────────────────────────────────────────
def build_dataset():
    csv_path = "data/phishing_email.csv"
    if os.path.exists(csv_path):
        print(f"[EMAIL] Loading Kaggle dataset from {csv_path}...")
        df = pd.read_csv(csv_path)
        text_col  = next((c for c in df.columns if 'text'  in c.lower() or 'body' in c.lower()), None)
        label_col = next((c for c in df.columns if 'label' in c.lower() or 'type' in c.lower()), None)
        if text_col and label_col:
            df = df[[text_col, label_col]].dropna()
            df.columns = ['text','label']
            df['label'] = df['label'].apply(
                lambda x: 1 if str(x).strip().lower() in ['1','phishing','spam','malicious'] else 0)
            print(f"[EMAIL] Loaded {len(df)} samples from Kaggle dataset")
            return df['text'].tolist(), df['label'].tolist()

    print("[EMAIL] Kaggle dataset not found — generating synthetic training data...")
    n = 5000
    texts  = [gen_phishing() for _ in range(n)] + [gen_safe() for _ in range(n)]
    labels = [1]*n + [0]*n
    combined = list(zip(texts, labels))
    random.shuffle(combined)
    texts, labels = zip(*combined)
    print(f"[EMAIL] Generated {len(texts)} synthetic samples ({n} phishing + {n} safe)")
    return list(texts), list(labels)

# ── Feature extraction ─────────────────────────────────────────────────────────
URGENCY_WORDS = ["immediately","urgent","suspended","verify","confirm","expire",
    "unusual","unauthorized","breach","click here","action required","limited time",
    "within 24","account locked","security alert","lose access","terminate"]
FEAR_WORDS    = ["terminated","suspended","blocked","unauthorized","breach","detected","failure"]
CRED_WORDS    = ["password","card number","bank account","ssn","date of birth",
    "credit card","debit card","pin","otp","cvv"]
BRAND_WORDS   = ["paypal","amazon","apple","google","microsoft","netflix","sbi","hdfc",
    "icici","facebook","instagram","twitter","linkedin"]

def handcrafted_features(texts):
    feats = []
    for text in texts:
        tl = text.lower()
        urls = re.findall(r'http\S+', tl)
        sus_urls = sum(1 for u in urls if any(s in u for s in ["bit.ly","tiny","tk","xyz","click"]) or not u.startswith("https"))
        feats.append([
            sum(1 for w in URGENCY_WORDS if w in tl),
            sum(1 for w in FEAR_WORDS    if w in tl),
            sum(1 for w in CRED_WORDS    if w in tl),
            sum(1 for w in BRAND_WORDS   if w in tl),
            len(urls), sus_urls,
            1 if re.search(r'\b(dear customer|dear user|dear member|dear valued)\b', tl) else 0,
            len(re.findall(r'\b[A-Z]{3,}\b', text)),
            text.count("!"),
            len(text.split()),
        ])
    return np.array(feats, dtype=float)

# ── Train ──────────────────────────────────────────────────────────────────────
texts, labels = build_dataset()
X_hand = handcrafted_features(texts)
y      = np.array(labels)

print("[EMAIL] Fitting TF-IDF vectorizer...")
tfidf  = TfidfVectorizer(max_features=3000, ngram_range=(1,2),
                          stop_words='english', sublinear_tf=True)
X_tfidf = tfidf.fit_transform(texts).toarray()
X_all   = np.hstack([X_hand, X_tfidf])

X_train,X_test,y_train,y_test = train_test_split(X_all, y, test_size=0.2,
                                                   random_state=42, stratify=y)
print("[EMAIL] Training Gradient Boosting classifier...")
model = GradientBoostingClassifier(n_estimators=200, max_depth=5,
                                    learning_rate=0.1, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
acc    = accuracy_score(y_test, y_pred)
print(f"\n[EMAIL] Accuracy: {acc*100:.2f}%")
print(classification_report(y_test, y_pred, target_names=["Safe","Phishing"]))

payload = {"model": model, "tfidf": tfidf, "accuracy": acc,
           "handcrafted_features_fn": "handcrafted_features",
           "feature_count_hand": X_hand.shape[1]}

with open("models/email_model.pkl","wb") as f:
    pickle.dump(payload, f)
print("✅ Email model saved to models/email_model.pkl")

# Sanity check
phish_text = "Dear Customer, your PayPal account SUSPENDED! Click http://bit.ly/fix IMMEDIATELY or lose access within 24 hours."
safe_text  = "Hi Priya, please find attached the monthly report. Let me know if you have questions. Best regards, Rajesh"

for txt, expected in [(phish_text,"PHISHING"),(safe_text,"SAFE")]:
    hf  = handcrafted_features([txt])
    tf  = tfidf.transform([txt]).toarray()
    xv  = np.hstack([hf, tf])
    prob = model.predict_proba(xv)[0][1]
    got  = "PHISHING" if prob>0.5 else "SAFE"
    ok   = "✅" if got==expected else "❌"
    print(f"{ok} {txt[:60]:<60} → {got} ({prob:.2f})")
