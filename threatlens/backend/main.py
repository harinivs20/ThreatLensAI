"""
main.py — ThreatLens AI Backend (FastAPI)
Run: uvicorn main:app --reload --port 8000 --host 0.0.0.0
"""
import os, uuid, io, csv

# Load .env manually
_env = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(_env):
    with open(_env) as f:
        for line in f:
            line=line.strip()
            if line and not line.startswith("#") and "=" in line:
                k,v=line.split("=",1)
                os.environ.setdefault(k.strip(),v.strip())

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional

from url_features   import extract_url_features, score_url_features
from email_features import extract_email_features, score_email_features
from campaign       import fingerprint_and_store, get_scan_history, get_stats, CAMPAIGNS
from explainer      import generate_explanation, generate_report_card_reasons
from shap_explain   import get_shap_values, get_rule_based_shap
from database       import init_db, save_scan, get_history as db_history
from database       import get_stats as db_stats, get_scan_by_id, get_history_for_export
from pdf_report     import generate_pdf_report

app = FastAPI(title="ThreatLens AI API", version="2.0.0")

app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_credentials=False,
    allow_methods=["*"], allow_headers=["*"])

# Init SQLite on startup
@app.on_event("startup")
def startup():
    init_db()
    from database import init_bulk_table
    init_bulk_table()

# ── Models ─────────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    input_type:  str
    input_value: str

# ── Helpers ────────────────────────────────────────────────────────────────────
def threat_level(risk):
    if risk>=80: return "CRITICAL"
    if risk>=60: return "HIGH"
    if risk>=40: return "MEDIUM"
    if risk>=20: return "LOW"
    return "NONE"

def run_scan(input_type: str, input_value: str) -> dict:
    input_type  = input_type.strip().lower()
    input_value = input_value.strip()
    if not input_value: raise HTTPException(400,"input_value cannot be empty")
    if input_type not in ("url","email"): raise HTTPException(400,"input_type must be url or email")

    if input_type=="url":
        raw    = extract_url_features(input_value)
        scores = score_url_features(raw)
        rc = {
            "domain_reputation": {**scores["domain_reputation"],
                "reason": generate_report_card_reasons("url","domain_reputation",scores["domain_reputation"]["score"],raw)},
            "link_safety":       {**scores["link_safety"],
                "reason": generate_report_card_reasons("url","link_safety",scores["link_safety"]["score"],raw)},
            "structure_risk":    {**scores["structure_risk"],
                "reason": generate_report_card_reasons("url","structure_risk",scores["structure_risk"]["score"],raw)},
            "keyword_risk":      {**scores["keyword_risk"],
                "reason": generate_report_card_reasons("url","keyword_risk",scores["keyword_risk"]["score"],raw)},
            "urgency_score":     None,
        }
        shap_vals = get_shap_values(raw) or get_rule_based_shap(raw,"url")
    else:
        raw    = extract_email_features(input_value)
        scores = score_email_features(raw)
        rc = {
            "sender_authenticity":    {**scores["sender_authenticity"],
                "reason": generate_report_card_reasons("email","sender_authenticity",scores["sender_authenticity"]["score"],raw)},
            "language_manipulation":  {**scores["language_manipulation"],
                "reason": generate_report_card_reasons("email","language_manipulation",scores["language_manipulation"]["score"],raw)},
            "credential_risk":        {**scores["credential_risk"],
                "reason": generate_report_card_reasons("email","credential_risk",scores["credential_risk"]["score"],raw)},
            "link_safety":            {**scores["link_safety"],
                "reason": generate_report_card_reasons("email","link_safety",scores["link_safety"]["score"],raw)},
            "urgency_score":          scores.get("urgency_score",0),
        }
        shap_vals = get_rule_based_shap(raw,"email")

    overall_risk = scores["overall_risk"]
    verdict      = "PHISHING" if overall_risk>=35 else "SAFE"
    confidence   = max(min(overall_risk if verdict=="PHISHING" else 100-overall_risk,99),50)
    tl           = threat_level(overall_risk)

    campaign = fingerprint_and_store(input_type,input_value,verdict,
        url_features=raw if input_type=="url" else None,
        email_features=raw if input_type=="email" else None,
        risk_scores={"overall_risk":overall_risk})

    explanation = generate_explanation(input_type,input_value,verdict,
        {"overall_risk":overall_risk}, raw, campaign)

    # Remove internal keys before returning
    clean_raw = {k:v for k,v in raw.items() if not k.startswith("_")}

    scan_id = str(uuid.uuid4())[:12]
    save_scan(scan_id, input_type, input_value, verdict, overall_risk, tl,
              confidence, campaign.get("id"), campaign.get("name"),
              explanation, rc, clean_raw, shap_vals)

    return {
        "id":               scan_id,
        "verdict":          verdict,
        "confidence":       confidence,
        "threat_level":     tl,
        "overall_risk":     overall_risk,
        "explanation":      explanation,
        "report_card":      rc,
        "campaign":         campaign,
        "features_summary": clean_raw,
        "shap_values":      shap_vals,
        "input_type":       input_type,
        "input_value":      input_value,
    }

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.get("/")
def root(): return {"message":"ThreatLens AI v2.0","status":"running"}

@app.get("/api/health")
def health(): return {"status":"ok","version":"2.0.0"}

@app.post("/api/scan")
def scan(req: ScanRequest):
    return run_scan(req.input_type, req.input_value)

@app.post("/api/bulk-scan")
async def bulk_scan(file: UploadFile = File(...)):
    """Parallel bulk scan — processes URLs concurrently for speed."""
    import concurrent.futures, uuid as _uuid
    from database import save_bulk_scan, init_bulk_table
    init_bulk_table()

    content   = await file.read()
    filename  = file.filename or "upload"
    lines     = content.decode("utf-8", "ignore").splitlines()
    reader    = csv.DictReader(lines)

    fieldnames = reader.fieldnames or []
    url_col    = next((c for c in fieldnames if "url" in c.lower()), None)
    if not url_col:
        urls = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
    else:
        urls = [row[url_col].strip() for row in reader if row.get(url_col, "").strip()]

    if len(urls) > 10000:
        raise HTTPException(400, "Maximum 10,000 URLs per bulk scan")

    def scan_url(url):
        try:
            r = run_scan("url", url)
            return {
                "url":          url,
                "verdict":      r["verdict"],
                "risk":         r["overall_risk"],
                "threat_level": r["threat_level"],
                "campaign":     r["campaign"].get("name", "") if r["campaign"] else "",
            }
        except Exception:
            return {"url": url, "verdict": "ERROR", "risk": 0, "threat_level": "UNKNOWN", "campaign": ""}

    # Parallel execution — 10 workers for speed
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        results = list(ex.map(scan_url, urls))

    phishing_count = sum(1 for r in results if r["verdict"] == "PHISHING")
    safe_count     = sum(1 for r in results if r["verdict"] == "SAFE")
    bulk_id        = str(_uuid.uuid4())[:12]

    save_bulk_scan(bulk_id, filename, len(results), phishing_count, safe_count, results)

    return {
        "id":       bulk_id,
        "total":    len(results),
        "phishing": phishing_count,
        "safe":     safe_count,
        "results":  results,
    }

@app.get("/api/bulk-history")
def bulk_history(limit: int = 20):
    from database import get_bulk_history, init_bulk_table
    init_bulk_table()
    return {"scans": get_bulk_history(limit)}

@app.get("/api/bulk-scan/{bulk_id}/csv")
def bulk_download_csv(bulk_id: str):
    from database import get_bulk_scan_by_id
    scan = get_bulk_scan_by_id(bulk_id)
    if not scan:
        raise HTTPException(404, "Bulk scan not found")
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["url","verdict","risk","threat_level","campaign"])
    writer.writeheader()
    writer.writerows(scan["results"])
    output.seek(0)
    safe_name = scan["filename"].replace(" ", "_").replace("(","").replace(")","")
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=threatlens-bulk-{safe_name}"}
    )

@app.get("/api/report/{scan_id}/pdf")
def download_pdf(scan_id: str):
    """Generate and download PDF report for a scan."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    pdf_bytes = generate_pdf_report(scan)
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=threatlens-report-{scan_id}.pdf"}
    )

@app.get("/api/history")
def history(limit: int = 20):
    try:
        return {"scans": db_history(limit)}
    except:
        return {"scans": get_scan_history(limit)}

@app.get("/api/stats")
def stats():
    try:
        return db_stats()
    except:
        return get_stats()

@app.get("/api/campaigns")
def campaigns_list():
    from threat_intel import get_discovered_campaigns
    local   = list(CAMPAIGNS.values())
    online  = get_discovered_campaigns(50)
    # Tag local ones
    for c in local:
        c["source"] = "Local Database"
        c["online"] = False
    return {"campaigns": local + online, "local_count": len(local), "online_count": len(online)}

@app.get("/api/export/csv")
def export_csv():
    """Export full scan history as CSV."""
    try:
        rows = get_history_for_export(500)
    except:
        rows = get_scan_history(500)
    
    output = io.StringIO()
    writer = csv.DictWriter(output,
        fieldnames=["id","input_type","input_value","verdict","overall_risk",
                    "threat_level","confidence","campaign_name","created_at"])
    writer.writeheader()
    writer.writerows(rows)
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition":"attachment; filename=threatlens-history.csv"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
