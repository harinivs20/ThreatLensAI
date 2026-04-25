"""
shap_explain.py — SHAP value computation for explainable AI.
Shows which features contributed most to each phishing verdict.
"""
import os, pickle
import numpy as np

_EXPLAINER = None

def _load_explainer():
    global _EXPLAINER
    if _EXPLAINER is None:
        try:
            import shap
            path = os.path.join(os.path.dirname(__file__), "models", "url_model.pkl")
            if os.path.exists(path):
                with open(path,"rb") as f:
                    mdl = pickle.load(f)
                _EXPLAINER = {
                    "explainer":     shap.TreeExplainer(mdl["model"]),
                    "feature_names": mdl["feature_names"],
                }
                print("[ThreatLens] SHAP explainer loaded ✅")
        except ImportError:
            print("[ThreatLens] SHAP not installed — run: pip install shap")
        except Exception as e:
            print(f"[ThreatLens] SHAP init failed: {e}")
    return _EXPLAINER

def get_shap_values(features: dict) -> list | None:
    """
    Compute SHAP values for a URL feature dict.
    Returns list of {feature, value, shap, impact} sorted by |shap| descending.
    """
    exp = _load_explainer()
    if exp is None:
        return None

    try:
        import shap
        feat_names = exp["feature_names"]
        feat_vec   = np.array([[features.get(n, 0) for n in feat_names]])
        shap_vals  = exp["explainer"].shap_values(feat_vec)

        # shap_values returns [class0_shaps, class1_shaps] for RF
        # We want class1 (phishing) shaps
        if isinstance(shap_vals, list):
            sv = shap_vals[1][0]
        else:
            sv = shap_vals[0]

        result = []
        for i, name in enumerate(feat_names):
            result.append({
                "feature": name,
                "value":   round(float(features.get(name, 0)), 4),
                "shap":    round(float(sv[i]), 4),
                "impact":  "increases_risk" if sv[i] > 0 else "decreases_risk",
            })

        # Sort by absolute SHAP value descending
        result.sort(key=lambda x: abs(x["shap"]), reverse=True)
        return result[:10]  # top 10 features

    except Exception as e:
        print(f"[SHAP] Error: {e}")
        return None

def get_rule_based_shap(features: dict, input_type: str) -> list:
    """
    Fallback rule-based feature importance when SHAP unavailable.
    Returns same format as SHAP output.
    """
    if input_type == "url":
        contributions = [
            ("uses_ip",          features.get("uses_ip",0)          * 40, "IP address used instead of domain"),
            ("sus_tld",          features.get("sus_tld",0)           * 30, "Suspicious top-level domain (.tk, .xyz)"),
            ("digit_mix",        features.get("digit_mix",0)         * 25, "Digits mixed into domain name"),
            ("has_at",           features.get("has_at",0)            * 25, "@ symbol in URL"),
            ("has_shortener",    features.get("has_shortener",0)     * 20, "URL shortener detected"),
            ("keyword_count",    features.get("keyword_count",0)     * 15, "Phishing keywords in URL"),
            ("uses_https",       (1-features.get("uses_https",1))    * 15, "No HTTPS encryption"),
            ("domain_entropy",   min(features.get("domain_entropy",0)/5*20,20), "High domain entropy (random-looking)"),
            ("excess_subdomain", features.get("excess_subdomain",0)  * 10, "Excessive subdomains"),
            ("url_length",       min(features.get("url_length",0)/200*10,10), "Abnormally long URL"),
        ]
    else:
        contributions = [
            ("credential_count",   features.get("credential_count",0) * 25, "Requests credentials/passwords"),
            ("brand_count",        features.get("brand_count",0)       * 20, "Brand impersonation detected"),
            ("fear_count",         features.get("fear_count",0)        * 18, "Fear-inducing language"),
            ("urgency_count",      features.get("urgency_count",0)     * 15, "Urgency trigger phrases"),
            ("generic_salutation", features.get("generic_salutation",0)* 15, "Generic greeting (Dear Customer)"),
            ("suspicious_urls",    features.get("suspicious_urls",0)   * 15, "Suspicious/shortened URLs"),
            ("caps_words",         min(features.get("caps_words",0)*3,10),   "Excessive CAPS words"),
            ("exclamation_count",  min(features.get("exclamation_count",0)*2,8), "Excessive exclamation marks"),
            ("url_count",          min(features.get("url_count",0)*3,8),     "Multiple links in email"),
        ]

    result = []
    for name, shap_val, desc in contributions:
        result.append({
            "feature":     name,
            "description": desc,
            "value":       round(float(features.get(name, 0)), 3),
            "shap":        round(float(shap_val) / 100, 4),
            "impact":      "increases_risk" if shap_val > 0 else "neutral",
        })
    result.sort(key=lambda x: abs(x["shap"]), reverse=True)
    return [r for r in result if r["shap"] != 0][:8]
