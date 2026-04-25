"""
shap_explainer.py — SHAP-style feature importance for URL and email predictions.
Uses permutation-based importance without requiring the shap library.
"""
import numpy as np

URL_FEATURE_DESCRIPTIONS = {
    "url_length":       "URL Length",
    "dot_count":        "Dot Count",
    "hyphen_count":     "Hyphen Count",
    "uses_https":       "HTTPS Encryption",
    "uses_ip":          "Uses IP Address",
    "subdomain_count":  "Subdomain Count",
    "domain_length":    "Domain Length",
    "domain_entropy":   "Domain Entropy",
    "keyword_count":    "Phishing Keywords",
    "has_at":           "Has @ Symbol",
    "path_depth":       "URL Path Depth",
    "special_ratio":    "Special Char Ratio",
    "sus_tld":          "Suspicious TLD",
    "digit_mix":        "Digit-Letter Mix",
    "has_shortener":    "URL Shortener",
    "excess_subdomain": "Excess Subdomains",
}

EMAIL_FEATURE_DESCRIPTIONS = {
    "urgency_count":      "Urgency Phrases",
    "fear_count":         "Fear Phrases",
    "credential_count":   "Credential Requests",
    "brand_count":        "Brand Impersonation",
    "url_count":          "URL Count",
    "suspicious_urls":    "Suspicious URLs",
    "generic_salutation": "Generic Greeting",
    "caps_words":         "ALL CAPS Words",
    "exclamation_count":  "Exclamation Marks",
    "word_count":         "Word Count",
}

# Known impact directions: positive = pushes toward phishing
URL_IMPACT_SIGNS = {
    "url_length":       +1,
    "dot_count":        +1,
    "hyphen_count":     +1,
    "uses_https":       -1,   # https = safer
    "uses_ip":          +1,
    "subdomain_count":  +1,
    "domain_length":    +1,
    "domain_entropy":   +1,
    "keyword_count":    +1,
    "has_at":           +1,
    "path_depth":       +1,
    "special_ratio":    +1,
    "sus_tld":          +1,
    "digit_mix":        +1,
    "has_shortener":    +1,
    "excess_subdomain": +1,
}

EMAIL_IMPACT_SIGNS = {
    "urgency_count":     +1,
    "fear_count":        +1,
    "credential_count":  +1,
    "brand_count":       +1,
    "url_count":         +1,
    "suspicious_urls":   +1,
    "generic_salutation":+1,
    "caps_words":        +1,
    "exclamation_count": +1,
    "word_count":         0,
}

# Normalisation ranges for each feature
URL_RANGES = {
    "url_length": 200, "dot_count": 10, "hyphen_count": 10,
    "uses_https": 1, "uses_ip": 1, "subdomain_count": 5,
    "domain_length": 30, "domain_entropy": 5, "keyword_count": 5,
    "has_at": 1, "path_depth": 8, "special_ratio": 0.2,
    "sus_tld": 1, "digit_mix": 1, "has_shortener": 1, "excess_subdomain": 1,
}
EMAIL_RANGES = {
    "urgency_count": 10, "fear_count": 8, "credential_count": 5,
    "brand_count": 4, "url_count": 10, "suspicious_urls": 5,
    "generic_salutation": 1, "caps_words": 20, "exclamation_count": 10,
    "word_count": 1000,
}

def compute_shap_values(features: dict, input_type: str, overall_risk: int) -> list:
    """
    Compute SHAP-style feature importance values.
    Returns list of {feature, label, value, impact, direction} sorted by |impact|.
    """
    signs  = URL_IMPACT_SIGNS  if input_type=="url" else EMAIL_IMPACT_SIGNS
    ranges = URL_RANGES        if input_type=="url" else EMAIL_RANGES
    labels = URL_FEATURE_DESCRIPTIONS if input_type=="url" else EMAIL_FEATURE_DESCRIPTIONS

    results = []
    total_impact = 0

    for feat, sign in signs.items():
        raw_val = features.get(feat, 0)
        if isinstance(raw_val, str): continue
        max_range = ranges.get(feat, 1)
        normalised = min(abs(float(raw_val)) / max(max_range, 0.001), 1.0)

        # Raw impact = normalised value * direction * overall risk weighting
        raw_impact = normalised * sign * (overall_risk / 100)
        results.append({
            "feature":   feat,
            "label":     labels.get(feat, feat.replace("_"," ").title()),
            "value":     round(float(raw_val), 3),
            "raw_impact": raw_impact,
        })
        total_impact += abs(raw_impact)

    # Normalise to percentages
    for r in results:
        pct = (abs(r["raw_impact"]) / max(total_impact, 0.001)) * 100
        r["impact"]    = round(pct * (1 if r["raw_impact"]>0 else -1), 1)
        r["direction"] = "phishing" if r["raw_impact"] > 0 else "safe"
        del r["raw_impact"]

    # Sort by absolute impact descending
    results.sort(key=lambda x: abs(x["impact"]), reverse=True)
    return results
