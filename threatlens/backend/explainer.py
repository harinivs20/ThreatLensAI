"""
explainer.py — AI explanation generator.
Uses Claude API if ANTHROPIC_API_KEY is set, otherwise uses rule-based fallback.
"""
import os

def _get_client():
    try:
        api_key = os.getenv("ANTHROPIC_API_KEY","")
        if api_key and api_key != "your_anthropic_api_key_here":
            from anthropic import Anthropic
            return Anthropic(api_key=api_key)
    except ImportError:
        pass
    return None

def generate_explanation(input_type, input_value, verdict, risk_scores, features, campaign):
    client = _get_client()
    if client:
        try:
            top = [f"{k}={v}" for k,v in features.items()
                   if isinstance(v,(int,float)) and v>0 and not k.startswith("_")][:8]
            camp_note = ""
            if campaign:
                camp_note = (f"Matches campaign '{campaign.get('name')}' targeting "
                           f"{campaign.get('total_orgs')} organisations.")
            prompt = (f"You are a cybersecurity analyst. Write 2-3 sentences explaining "
                     f"why this {input_type} was classified as {verdict}.\n"
                     f"Input: {str(input_value)[:120]}\n"
                     f"Key signals: {', '.join(top)}\n"
                     f"Overall risk: {risk_scores.get('overall_risk',0)}/100\n"
                     f"{camp_note}\n"
                     f"Rules: plain English, specific, no jargon, max 3 sentences.")
            resp = client.messages.create(
                model="claude-sonnet-4-20250514", max_tokens=200,
                messages=[{"role":"user","content":prompt}]
            )
            return resp.content[0].text.strip()
        except Exception:
            pass
    return _rule_explanation(input_type, input_value, verdict, risk_scores, features, campaign)

def _rule_explanation(input_type, input_value, verdict, risk_scores, features, campaign):
    if verdict == "SAFE":
        if input_type == "url":
            return ("This URL uses HTTPS encryption, has a clean legitimate domain, "
                   "and contains no phishing keywords or suspicious patterns. "
                   "No known phishing indicators were detected.")
        return ("This email shows no significant urgency signals, brand impersonation, "
               "or credential harvesting language. It appears to be legitimate.")

    signals = []
    if input_type == "url":
        if features.get("uses_ip"):           signals.append("uses an IP address instead of a proper domain name")
        if not features.get("uses_https"):    signals.append("does not use HTTPS encryption")
        if features.get("sus_tld"):           signals.append("uses a free/suspicious TLD (.tk, .xyz, etc.) commonly used by attackers")
        if features.get("digit_mix"):         signals.append("uses digit substitution to impersonate a real brand (e.g. paypa1, amaz0n)")
        if features.get("keyword_count",0)>=2:signals.append("contains multiple phishing keywords like 'verify', 'login', or 'secure'")
        if features.get("has_at"):            signals.append("contains an @ symbol to mask the real destination")
        if features.get("has_shortener"):     signals.append("uses a URL shortener to hide the real destination")
    else:
        if features.get("urgency_count",0)>0: signals.append("uses urgency language to pressure you into immediate action")
        if features.get("generic_salutation"):signals.append("uses a generic greeting with no personalisation (common phishing pattern)")
        if features.get("brand_count",0)>0:   signals.append("impersonates a well-known brand")
        if features.get("credential_count",0)>0: signals.append("requests sensitive credentials or personal information")

    sig_str = " and ".join(signals[:3]) if signals else "multiple suspicious patterns"
    camp_str = ""
    if campaign and campaign.get("name"):
        camp_str = (f" This attack matches the '{campaign['name']}' campaign which has "
                   f"targeted {campaign.get('total_orgs',0)} organisations.")

    return (f"This {input_type} was flagged because it {sig_str}. "
           f"These are classic techniques used by attackers to steal credentials.{camp_str}")

def generate_report_card_reasons(input_type, dimension, score, features):
    reasons = {
        "url": {
            "domain_reputation": {
                "high":   "Domain uses digit substitution or random characters to mimic a trusted brand.",
                "medium": "Domain is newly registered or uses an unusual top-level domain.",
                "low":    "Domain appears legitimate and is well-established.",
            },
            "link_safety": {
                "high":   "Link lacks HTTPS and uses redirect tricks or @ symbol to mask the destination.",
                "medium": "Link uses HTTP or contains a URL shortener hiding the true destination.",
                "low":    "Link uses HTTPS and resolves to a clean legitimate domain.",
            },
            "structure_risk": {
                "high":   "URL is abnormally long with excessive subdomains and special characters.",
                "medium": "URL has some structural anomalies like extra hyphens or deep path.",
                "low":    "URL structure is clean and follows normal patterns.",
            },
            "keyword_risk": {
                "high":   "URL contains multiple phishing keywords such as 'verify', 'login', or 'secure'.",
                "medium": "URL contains one suspicious keyword.",
                "low":    "No phishing keywords detected in the URL.",
            },
        },
        "email": {
            "sender_authenticity": {
                "high":   "Email uses a generic greeting and impersonates a known brand.",
                "medium": "Sender details have minor inconsistencies.",
                "low":    "Sender details appear legitimate.",
            },
            "language_manipulation": {
                "high":   "Email contains multiple urgency triggers and fear-inducing phrases.",
                "medium": "Email uses some urgency language to prompt quick action.",
                "low":    "No significant urgency or manipulation language detected.",
            },
            "credential_risk": {
                "high":   "Email explicitly requests passwords, bank details, or personal credentials.",
                "medium": "Email hints at needing account verification.",
                "low":    "No credential harvesting language found.",
            },
            "link_safety": {
                "high":   "Email contains shortened or unencrypted URLs.",
                "medium": "Email contains links that do not fully use HTTPS.",
                "low":    "All links in the email appear safe.",
            },
        },
    }
    level = "high" if score>=60 else ("medium" if score>=30 else "low")
    return reasons.get(input_type,{}).get(dimension,{}).get(level,"Analysis unavailable.")
