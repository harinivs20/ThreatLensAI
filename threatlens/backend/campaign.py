"""
campaign.py — Attack fingerprinting and campaign intelligence.
"""
import math, uuid
from datetime import datetime
from typing import Optional

THREAT_DB: list[dict] = []

CAMPAIGNS = {
"camp-001": {"id":"camp-001","name":"PayPal Clone Group #7","description":"Credential harvesting using .tk/.ml domains with digit substitution (paypa1, paypai).","org_types":{"Educational Institutions":7,"Banks / Financial Services":3,"E-commerce Platforms":2,"Healthcare Organisations":1},"first_seen":"2025-01-14","last_seen":"2025-03-10","region":"South India","total_orgs":13,"template":"paypal-clone","vec":[0.85,0.90,0.70,0.80,0.75,0.60,0.85,0.90,0.50,0.65,0.40,0.30]},
"camp-002": {"id":"camp-002","name":"SBI NetBanking Fraud Ring","description":"SMS and email phishing cloning SBI internet banking login pages.","org_types":{"Educational Institutions":4,"Banks / Financial Services":8,"Government Portals":3,"Small Businesses":2},"first_seen":"2025-02-01","last_seen":"2025-03-15","region":"Tamil Nadu, Karnataka","total_orgs":17,"template":"sbi-clone","vec":[0.75,0.80,0.60,0.90,0.65,0.50,0.75,0.80,0.70,0.55,0.45,0.35]},
"camp-003": {"id":"camp-003","name":"College IT Credential Harvesters","description":"Fake university login portals, exam result pages, and scholarship forms targeting students.","org_types":{"Educational Institutions":11,"E-commerce Platforms":2,"Job Portals":1},"first_seen":"2025-01-20","last_seen":"2025-03-18","region":"Tamil Nadu","total_orgs":14,"template":"university-clone","vec":[0.60,0.55,0.80,0.65,0.90,0.70,0.60,0.55,0.40,0.75,0.50,0.45]},
"camp-004": {"id":"camp-004","name":"Amazon India Package Scam","description":"Fake delivery failure notifications and package tracking pages impersonating Amazon India.","org_types":{"E-commerce Platforms":5,"Logistics / Delivery":3,"Banks / Financial Services":4,"General Public":9},"first_seen":"2025-01-05","last_seen":"2025-03-20","region":"Pan India","total_orgs":21,"template":"amazon-clone","vec":[0.78,0.82,0.65,0.88,0.72,0.55,0.78,0.85,0.60,0.70,0.48,0.38]},
"camp-005": {"id":"camp-005","name":"HDFC KYC Expiry Gang","description":"Mass phishing with fake KYC expiry alerts — 'complete KYC in 24 hours or account blocked'.","org_types":{"Banks / Financial Services":6,"Educational Institutions":3,"Healthcare Organisations":2,"Government Portals":2},"first_seen":"2025-02-10","last_seen":"2025-03-19","region":"Maharashtra, Gujarat, Delhi","total_orgs":13,"template":"hdfc-kyc-clone","vec":[0.80,0.78,0.72,0.85,0.68,0.58,0.80,0.75,0.65,0.60,0.52,0.42]},
"camp-006": {"id":"camp-006","name":"Microsoft 365 Credential Phish","description":"Corporate employees targeted with fake Microsoft 365 login pages on lookalike domains like micros0ft-login.com.","org_types":{"IT / Tech Companies":8,"Banks / Financial Services":5,"Educational Institutions":6,"Healthcare Organisations":3,"Government Portals":2},"first_seen":"2024-12-15","last_seen":"2025-03-17","region":"Bengaluru, Hyderabad, Pune","total_orgs":24,"template":"microsoft-365-clone","vec":[0.88,0.85,0.75,0.92,0.80,0.65,0.88,0.92,0.70,0.78,0.55,0.48]},
"camp-007": {"id":"camp-007","name":"IRCTC Ticket Refund Scammers","description":"Fake IRCTC refund portal asking users to enter debit card details to receive fake train ticket refunds.","org_types":{"Government Portals":4,"Banks / Financial Services":5,"Educational Institutions":3,"General Public":7},"first_seen":"2025-01-28","last_seen":"2025-03-12","region":"North India, Tamil Nadu","total_orgs":19,"template":"irctc-refund-clone","vec":[0.72,0.68,0.78,0.82,0.62,0.52,0.72,0.70,0.75,0.58,0.48,0.40]},
"camp-008": {"id":"camp-008","name":"Google Account Suspension Wave","description":"Fake Google account suspension warnings redirecting to cloned Gmail login pages on .xyz and .click domains.","org_types":{"Educational Institutions":14,"IT / Tech Companies":6,"Small Businesses":5,"Healthcare Organisations":2},"first_seen":"2025-01-10","last_seen":"2025-03-21","region":"Pan India","total_orgs":27,"template":"google-suspension-clone","vec":[0.82,0.88,0.68,0.85,0.78,0.62,0.82,0.88,0.55,0.72,0.50,0.44]},
"camp-009": {"id":"camp-009","name":"Job Portal Fake Recruiter Ring","description":"Attackers posing as recruiters sending fake offer letters with links to credential-harvesting HR portals.","org_types":{"Job Portals / Recruitment":6,"Educational Institutions":9,"IT / Tech Companies":7,"General Public":5},"first_seen":"2025-02-05","last_seen":"2025-03-18","region":"Bengaluru, Chennai, Hyderabad","total_orgs":27,"template":"fake-recruiter-portal","vec":[0.65,0.60,0.82,0.70,0.85,0.68,0.65,0.62,0.80,0.55,0.52,0.44]},
"camp-010": {"id":"camp-010","name":"Electricity Bill OTP Fraud","description":"Fake TNEB and APSPDCL bill payment pages claiming electricity disconnection to steal OTPs and debit card details.","org_types":{"Government Portals":5,"Banks / Financial Services":4,"General Public":12,"Small Businesses":3},"first_seen":"2025-02-18","last_seen":"2025-03-19","region":"Tamil Nadu, Andhra Pradesh","total_orgs":24,"template":"electricity-board-clone","vec":[0.70,0.65,0.75,0.80,0.60,0.50,0.70,0.68,0.72,0.55,0.45,0.38]},
"camp-011": {"id":"camp-011","name":"Aadhaar-Linked Account Freeze Scam","description":"Fake UIDAI emails claiming Aadhaar-linked bank account will be frozen. Redirects to fake Aadhaar portal for biometric verification.","org_types":{"Government Portals":7,"Banks / Financial Services":6,"Educational Institutions":4,"General Public":8},"first_seen":"2024-11-20","last_seen":"2025-02-28","region":"Kerala, Tamil Nadu, Karnataka","total_orgs":25,"template":"uidai-aadhaar-clone","vec":[0.68,0.62,0.76,0.84,0.58,0.48,0.68,0.65,0.70,0.52,0.42,0.36]},
"camp-012": {"id":"camp-012","name":"Flipkart Big Billion Sale Phish","description":"Lookalike Flipkart pages offering fake Big Billion Day deals requiring OTP and card details to claim discounts.","org_types":{"E-commerce Platforms":6,"Banks / Financial Services":5,"General Public":11,"Small Businesses":2},"first_seen":"2025-01-15","last_seen":"2025-03-08","region":"Pan India","total_orgs":24,"template":"flipkart-sale-clone","vec":[0.76,0.80,0.64,0.86,0.70,0.54,0.76,0.82,0.58,0.68,0.46,0.36]},
"camp-013": {"id":"camp-013","name":"COVID Vaccine Certificate Fraud","description":"Fake CoWIN certificate update pages collecting Aadhaar numbers and OTPs under the pretext of updating vaccination records.","org_types":{"Government Portals":6,"Healthcare Organisations":8,"Educational Institutions":5,"General Public":6},"first_seen":"2024-12-01","last_seen":"2025-02-15","region":"Pan India","total_orgs":25,"template":"cowin-certificate-clone","vec":[0.62,0.58,0.74,0.78,0.56,0.46,0.62,0.60,0.68,0.50,0.40,0.32]},
"camp-014": {"id":"camp-014","name":"WhatsApp OTP Hijack Campaign","description":"Phishing messages claiming WhatsApp account needs re-verification. Victims enter OTP allowing attackers to take over accounts.","org_types":{"General Public":18,"Educational Institutions":5,"Small Businesses":3},"first_seen":"2025-02-20","last_seen":"2025-03-21","region":"Pan India","total_orgs":26,"template":"whatsapp-otp-clone","vec":[0.58,0.55,0.72,0.76,0.54,0.44,0.58,0.58,0.65,0.48,0.38,0.30]},
"camp-015": {"id":"camp-015","name":"Income Tax Refund Phishing Wave","description":"Fake IT Department emails offering tax refunds. Victims are redirected to cloned incometax.gov.in pages to enter banking details.","org_types":{"Government Portals":4,"Banks / Financial Services":7,"Educational Institutions":3,"IT / Tech Companies":4,"General Public":7},"first_seen":"2025-01-01","last_seen":"2025-03-15","region":"Pan India","total_orgs":25,"template":"incometax-refund-clone","vec":[0.74,0.70,0.78,0.88,0.64,0.52,0.74,0.72,0.74,0.56,0.46,0.40]},
}

def _cosine_similarity(a, b):
    dot = sum(x*y for x,y in zip(a,b))
    na  = math.sqrt(sum(x*x for x in a))
    nb  = math.sqrt(sum(x*x for x in b))
    return dot/(na*nb) if na and nb else 0.0

def _build_vec(input_type, url_features=None, email_features=None, risk_scores=None):
    vec = [0.0]*12
    if input_type=="url" and url_features:
        f=url_features
        vec[0]=min(f.get("url_length",0)/200,1.0)
        vec[1]=min(f.get("dot_count",0)/10,1.0)
        vec[2]=min(f.get("hyphen_count",0)/10,1.0)
        vec[3]=1.0-f.get("uses_https",1)
        vec[4]=float(f.get("uses_ip",0))
        vec[5]=min(f.get("subdomain_count",0)/5,1.0)
        vec[6]=min(f.get("domain_length",0)/30,1.0)
        vec[7]=min(f.get("domain_entropy",0)/5,1.0)
        vec[8]=min(f.get("keyword_count",0)/5,1.0)
        vec[9]=float(f.get("has_at",0))
        vec[10]=min(f.get("path_depth",0)/8,1.0)
        vec[11]=min(f.get("special_ratio",0)*5,1.0)
    elif input_type=="email" and email_features:
        f=email_features
        vec[0]=min(f.get("urgency_count",0)/5,1.0)
        vec[1]=min(f.get("fear_count",0)/5,1.0)
        vec[2]=min(f.get("credential_count",0)/4,1.0)
        vec[3]=min(f.get("brand_count",0)/3,1.0)
        vec[4]=min(f.get("url_count",0)/5,1.0)
        vec[5]=min(f.get("suspicious_urls",0)/3,1.0)
        vec[6]=float(f.get("generic_salutation",0))
        vec[7]=min(f.get("caps_words",0)/10,1.0)
        vec[8]=min(f.get("exclamation_count",0)/5,1.0)
        vec[9]=0.5; vec[10]=0.3; vec[11]=0.2
    if risk_scores:
        r=risk_scores.get("overall_risk",0)/100
        vec=[((v+r)/2) for v in vec]
    return vec

def find_campaign(vec, threshold=0.80):
    best_sim, best_camp = 0.0, None
    for camp in CAMPAIGNS.values():
        sim = _cosine_similarity(vec, camp["vec"])
        if sim > best_sim and sim >= threshold:
            best_sim, best_camp = sim, camp
    return {**best_camp, "similarity": round(best_sim*100,1)} if best_camp else {}

def fingerprint_and_store(input_type, input_value, verdict,
                          url_features=None, email_features=None, risk_scores=None):
    vec      = _build_vec(input_type, url_features, email_features, risk_scores)
    campaign = find_campaign(vec) if verdict=="PHISHING" else {}

    # If no local match and it's a phishing URL — try live threat intel APIs
    if not campaign and verdict == "PHISHING" and input_type == "url":
        try:
            from threat_intel import lookup_url_online, save_online_campaign_to_db
            online = lookup_url_online(input_value)
            if online:
                save_online_campaign_to_db(online)
                campaign = online
                print(f"[Campaign] Online match: {online.get('name')} via {online.get('source')}")
        except Exception as e:
            print(f"[Campaign] Online lookup error: {e}")

    THREAT_DB.append({
        "id":          str(uuid.uuid4())[:8],
        "input_type":  input_type,
        "input_value": input_value[:80],
        "verdict":     verdict,
        "timestamp":   datetime.now().isoformat(),
        "campaign_id": campaign.get("id"),
    })
    return campaign

def get_scan_history(limit=20):
    recent = sorted(THREAT_DB, key=lambda x: x["timestamp"], reverse=True)
    return [{
        "id":          e["id"],
        "input_type":  e["input_type"],
        "input_value": e["input_value"],
        "verdict":     e["verdict"],
        "timestamp":   e["timestamp"],
        "campaign":    CAMPAIGNS.get(e["campaign_id"],{}).get("name") if e["campaign_id"] else None,
    } for e in recent[:limit]]

def get_stats():
    total    = len(THREAT_DB)
    phishing = sum(1 for e in THREAT_DB if e["verdict"]=="PHISHING")
    return {"total_scanned":total,"phishing_found":phishing,"safe_found":total-phishing,
            "blocked":phishing,"campaigns_seen":len(set(e["campaign_id"] for e in THREAT_DB if e["campaign_id"]))}
