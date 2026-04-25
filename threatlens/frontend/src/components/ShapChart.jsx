import React from 'react';
import './ShapChart.css';

const LABELS = {
  uses_ip:'IP Address Used',sus_tld:'Suspicious TLD (.tk/.xyz)',digit_mix:'Digit Substitution in Domain',
  has_at:'@ Symbol in URL',has_shortener:'URL Shortener Detected',keyword_count:'Phishing Keywords',
  uses_https:'No HTTPS Encryption',domain_entropy:'High Domain Entropy',excess_subdomain:'Excessive Subdomains',
  url_length:'Abnormal URL Length',credential_count:'Credential Harvest Language',brand_count:'Brand Impersonation',
  fear_count:'Fear-Inducing Language',urgency_count:'Urgency Trigger Phrases',generic_salutation:'Generic Greeting',
  suspicious_urls:'Suspicious Links in Email',caps_words:'Excessive CAPS',exclamation_count:'Exclamation Marks',
};

export default function ShapChart({ shapValues }) {
  if (!shapValues?.length) return null;
  const max = Math.max(...shapValues.map(s=>Math.abs(s.shap)), 0.001);
  return (
    <div className="card shap-card">
      <div className="section-title">🔬 Explainable AI — Feature Importance (SHAP)</div>
      <p className="shap-sub">Which features contributed most to this verdict</p>
      <div className="shap-list">
        {shapValues.slice(0,8).map((sv,i) => {
          const isRisk = sv.impact === 'increases_risk';
          const w = Math.abs(sv.shap)/max*100;
          const col = isRisk ? '#C00000' : '#166534';
          const label = sv.description || LABELS[sv.feature] || sv.feature.replace(/_/g,' ');
          return (
            <div key={i} className="shap-row">
              <div className="shap-label">{label}</div>
              <div className="shap-bar-wrap">
                <div className="shap-track"><div className="shap-fill" style={{width:`${w}%`,background:col}}/></div>
                <span className="shap-val" style={{color:col}}>{isRisk?'↑':'↓'} {Math.abs(sv.shap).toFixed(3)}</span>
              </div>
              <div className="shap-impact" style={{color:col}}>{isRisk?'Increases Risk':'Reduces Risk'}</div>
            </div>
          );
        })}
      </div>
      <div className="shap-legend">
        <span style={{color:'#C00000'}}>■ Increases phishing risk</span>
        <span style={{color:'#166534'}}>■ Reduces phishing risk</span>
      </div>
    </div>
  );
}
