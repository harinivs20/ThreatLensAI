import React from 'react';
import './ReportCard.css';

const GRADE_COL = { A:'#166534', B:'#2563eb', C:'#D97706', D:'#EA580C', F:'#C00000' };
const GRADE_BG  = { A:'#f0fdf4', B:'#eff6ff', C:'#fffbeb', D:'#fff7ed', F:'#fef2f2' };

function DimRow({ label, grade, score, reason }) {
  const col = GRADE_COL[grade] || '#64748b';
  const bg  = GRADE_BG[grade]  || '#f8fafc';
  return (
    <div className="dim-row">
      <div className="dim-top">
        <span className="dim-label">{label}</span>
        <div className="dim-right">
          <div className="dim-bar-track"><div className="dim-bar-fill" style={{width:`${score}%`,background:col}}/></div>
          <span className="dim-score">{score}/100</span>
          <span className="dim-grade" style={{color:col,background:bg,border:`1px solid ${col}33`}}>{grade}</span>
        </div>
      </div>
      <div className="dim-reason">{reason}</div>
    </div>
  );
}

export default function ReportCard({ reportCard, inputType }) {
  if (!reportCard) return null;
  const urlDims = [
    {key:'domain_reputation', label:'🌐 Domain Reputation'},
    {key:'link_safety',       label:'🔗 Link Safety'},
    {key:'structure_risk',    label:'🏗️ URL Structure'},
    {key:'keyword_risk',      label:'🔑 Keyword Risk'},
  ];
  const emailDims = [
    {key:'sender_authenticity',   label:'📧 Sender Authenticity'},
    {key:'language_manipulation', label:'💬 Language Manipulation'},
    {key:'credential_risk',       label:'🔐 Credential Risk'},
    {key:'link_safety',           label:'🔗 Link Safety'},
  ];
  const dims = inputType === 'url' ? urlDims : emailDims;
  return (
    <div className="card rc-card">
      <div className="section-title">📋 Threat Report Card</div>
      <div className="rc-dims">
        {dims.map(d => {
          const data = reportCard[d.key];
          if (!data) return null;
          return <DimRow key={d.key} label={d.label} grade={data.grade} score={data.score} reason={data.reason}/>;
        })}
      </div>
      {reportCard.urgency_score != null && (
        <div className="rc-urgency">
          <span>⚡ Urgency Score</span>
          <strong style={{color: reportCard.urgency_score>=7?'#C00000':reportCard.urgency_score>=4?'#D97706':'#166534'}}>
            {reportCard.urgency_score} / 10
          </strong>
        </div>
      )}
    </div>
  );
}
