# 🛡️ ThreatLens AI — Unified Phishing Intelligence Platform



---

## 📁 Project Structure

```
threatlens/
├── backend/
│   ├── main.py              ← FastAPI server (start here)
│   ├── url_features.py      ← URL feature extractor
│   ├── email_features.py    ← Email NLP feature extractor
│   ├── campaign.py          ← Fingerprinting + campaign database
│   ├── explainer.py         ← Claude AI explanation generator
│   ├── requirements.txt     ← Python dependencies
│   └── .env.example         ← Copy to .env and add your API key
│
└── frontend/
    ├── public/index.html
    ├── package.json
    └── src/
        ├── App.js
        ├── index.js
        ├── index.css
        ├── api/api.js
        ├── components/
        │   ├── Navbar.js / .css
        │   ├── VerdictBadge.js / .css
        │   ├── ReportCard.js / .css
        │   └── CampaignCard.js / .css
        └── pages/
            ├── Scanner.js / .css
            ├── Dashboard.js / .css
            ├── Campaigns.js / .css
            └── About.js / .css
```

---

## ⚙️ Setup Instructions

### Prerequisites
- Python 3.10+
- Node.js 18+
- VS Code (recommended)

---

### 🐍 Backend Setup

**Step 1 — Open a terminal in VS Code and navigate to the backend folder:**
```bash
cd threatlens/backend
```

**Step 2 — Create a virtual environment:**
```bash
python -m venv venv
```

**Step 3 — Activate the virtual environment:**

Windows:
```bash
venv\Scripts\activate
```
Mac/Linux:
```bash
source venv/bin/activate
```

**Step 4 — Install dependencies:**
```bash
pip install -r requirements.txt
```

**Step 5 — Download spaCy English model:**
```bash
python -m spacy download en_core_web_sm
```

**Step 6 — Set up your API key (optional but recommended):**
```bash
# Copy the example env file
cp .env.example .env
# Open .env and replace: your_anthropic_api_key_here
# with your actual key from https://console.anthropic.com
```
> ℹ️ The app works without an API key — it uses rule-based explanations as fallback.

**Step 7 — Start the backend server:**
```bash
uvicorn main:app --reload --port 8000
```

✅ Backend is running at: **http://localhost:8000**
📖 API docs at: **http://localhost:8000/docs**

---

### ⚛️ Frontend Setup

**Step 1 — Open a NEW terminal in VS Code:**
```bash
cd threatlens/frontend
```

**Step 2 — Install Node dependencies:**
```bash
npm install
```

**Step 3 — Start the React dev server:**
```bash
npm start
```

 Frontend is running at: **http://localhost:3000**

---

## How to Use

1. Open **http://localhost:3000** in your browser
2. Click **🔍 Scanner** tab
3. Choose **URL** or **Email** input type
4. Paste a suspicious URL or email (or click a Sample button)
5. Click **Analyse Now**
6. See the 5-layer result:
   - ✅/🚨 **Verdict** — SAFE or PHISHING with confidence
   - 🤖 **AI Explanation** — plain English reason
   - 📋 **Threat Report Card** — 5 dimension grades
   - 🗺️ **Campaign Intelligence** — how many orgs attacked
7. Check **📊 Dashboard** for session stats and history
8. Check **🗺️ Campaigns** for known attacker group profiles

---

 Test Inputs

### Phishing URLs (will score HIGH/CRITICAL):
```
http://paypa1-secure-login.tk/verify?id=usr123
http://amaz0n-account-suspended.xyz/reactivate
http://192.168.1.1/admin/login.php?session=abc
```

### Safe URLs (will score SAFE):
```
https://google.com/search?q=cybersecurity
https://github.com/
```

### Phishing Email:
```
From: noreply@paypai-support.com
Subject: URGENT: Your account will be SUSPENDED!

Dear Valued Customer,
We have detected unusual login. Click here IMMEDIATELY: http://bit.ly/fix-now
or you will lose access within 24 hours.
- PayPal Security Team
```

---

 API Endpoints

| Method | Endpoint        | Description                    |
|--------|----------------|-------------------------------|
| POST   | /api/scan       | Main scan endpoint             |
| GET    | /api/history    | Recent scan history            |
| GET    | /api/stats      | Session statistics             |
| GET    | /api/campaigns  | Known campaign list            |
| GET    | /api/health     | Health check                   |

