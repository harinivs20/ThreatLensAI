import React from 'react';
import './VerdictBadge.css';

const LEVEL_COLOR = { CRITICAL:'#C00000', HIGH:'#EA580C', MEDIUM:'#D97706', LOW:'#2563eb', NONE:'#166534' };

export default function VerdictBadge({ verdict, confidence, threatLevel, risk }) {
  const isPhish = verdict === 'PHISHING';
  const col = LEVEL_COLOR[threatLevel] || '#166534';
  return (
    <div className={`vb ${isPhish ? 'vb-phish' : 'vb-safe'}`}>
      <div className="vb-icon">{isPhish ? '🚨' : '✅'}</div>
      <div className="vb-body">
        <div className="vb-verdict" style={{color:col}}>{verdict}</div>
        <div className="vb-meta">
          <span className="vb-conf">{confidence}% confidence</span>
          <span className="vb-sep">·</span>
          <span className="vb-level" style={{background:col}}>{threatLevel}</span>
        </div>
      </div>
      <div className="vb-score-wrap">
        <svg viewBox="0 0 72 72" className="vb-ring">
          <circle cx="36" cy="36" r="28" className="ring-bg"/>
          <circle cx="36" cy="36" r="28" className="ring-fill"
            style={{stroke:col, strokeDasharray:`${risk*1.759} 176`}}/>
        </svg>
        <div className="vb-score-center">
          <div className="vb-score-num" style={{color:col}}>{risk}</div>
          <div className="vb-score-lbl">Risk</div>
        </div>
      </div>
    </div>
  );
}
