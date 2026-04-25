import React, { useState } from 'react';
import { scanInput } from '../api/api.jsx';
import VerdictBadge  from '../components/VerdictBadge.jsx';
import ReportCard    from '../components/ReportCard.jsx';
import CampaignCard  from '../components/CampaignCard.jsx';
import ShapChart     from '../components/ShapChart.jsx';
import './Scanner.css';

const URL_SAMPLES = [
  'http://paypa1-secure-login.tk/verify?id=usr123',
  'https://google.com/search?q=cybersecurity',
  'http://amaz0n-account-suspended.xyz/reactivate',
];
const EMAIL_SAMPLES = [
  `From: noreply@paypai-support.com\nSubject: URGENT: Your account will be SUSPENDED!\n\nDear Valued Customer,\nWe detected unusual login. Click IMMEDIATELY: http://bit.ly/fix-now\nor you will lose access within 24 hours.\n- PayPal Security Team`,
  `From: hr@company.com\nSubject: Monthly Newsletter\n\nHi team! Hope everyone is doing well. Please find attached the monthly digest. Have a great weekend!`,
];

export default function Scanner() {
  const [inputType,  setInputType]  = useState('url');
  const [inputValue, setInputValue] = useState('');
  const [loading,    setLoading]    = useState(false);
  const [result,     setResult]     = useState(null);
  const [error,      setError]      = useState('');

  async function handleScan() {
    if (!inputValue.trim()) { setError('Please enter a URL or email text.'); return; }
    setLoading(true); setError(''); setResult(null);
    try {
      const { data } = await scanInput(inputType, inputValue.trim());
      setResult(data);
    } catch(e) {
      setError(e?.code==='ERR_NETWORK'
        ? 'Cannot reach backend. Make sure uvicorn is running on port 8000.'
        : e?.response?.data?.detail || e.message || 'Unknown error');
    } finally { setLoading(false); }
  }

  const samples = inputType==='url' ? URL_SAMPLES : EMAIL_SAMPLES;

  return (
    <div className="scanner-page">
      <div className="scanner-hero">
        <h1>🛡️ ThreatLens AI Scanner</h1>
        <p>Paste a suspicious URL or email to run through our 5-layer intelligence pipeline.</p>
      </div>
      <div className="scanner-layout">
        {/* Input panel */}
        <div className="card input-panel">
          <div className="type-tabs">
            {['url','email'].map(t=>(
              <button key={t} className={`type-tab ${inputType===t?'active':''}`}
                onClick={()=>{setInputType(t);setInputValue('');setResult(null);setError('');}}>
                {t==='url'?'🔗 URL':'📧 Email'}
              </button>
            ))}
          </div>
          <textarea className="scan-input"
            rows={inputType==='email'?7:3}
            placeholder={inputType==='url'
              ?'Paste a suspicious URL here...\ne.g. http://paypa1-login.tk/verify'
              :'Paste full email content here...\n(Include From:, Subject:, body)'}
            value={inputValue}
            onChange={e=>{setInputValue(e.target.value);setError('');}}
          />
          <div className="sample-row">
            <span className="sample-lbl">💡 Try a sample:</span>
            {samples.map((s,i)=>(
              <button key={i} className="sample-btn"
                onClick={()=>{setInputValue(s);setResult(null);setError('');}}>
                Sample {i+1}
              </button>
            ))}
            {inputValue && (
              <button className="clear-btn"
                onClick={()=>{setInputValue('');setResult(null);setError('');}}>
                ✕ Clear
              </button>
            )}
          </div>
          {error && <div className="scan-error">⚠️ {error}</div>}
          <button className={`scan-btn${loading?' loading':''}`}
            onClick={handleScan} disabled={loading||!inputValue.trim()}>
            {loading ? '⏳ Analysing...' : '🚀 Analyse Now'}
          </button>
        </div>

        {/* Results panel */}
        {result && (
          <div className="results-panel fade-up">
            <VerdictBadge verdict={result.verdict} confidence={result.confidence}
              threatLevel={result.threat_level} risk={result.overall_risk}/>

            <div className="result-actions">
              <button className="btn btn-ghost btn-sm"
                onClick={()=>window.open(`http://localhost:8000/api/report/${result.id}/pdf`,'_blank')}>
                📄 Download PDF Report
              </button>
              <button className="btn btn-ghost btn-sm"
                onClick={()=>{setResult(null);setInputValue('');}}>
                ✕ Clear Results
              </button>
            </div>

            <div className="card explanation-box">
              <div className="exp-label">🤖 AI Analysis</div>
              <p className="exp-text">{result.explanation}</p>
            </div>

            <ReportCard reportCard={result.report_card} inputType={inputType}/>
            {result.shap_values?.length>0 && <ShapChart shapValues={result.shap_values}/>}
            <CampaignCard campaign={result.campaign}/>

            <details className="card raw-details">
              <summary>📊 Raw Features Extracted</summary>
              <pre className="raw-pre">{JSON.stringify(result.features_summary,null,2)}</pre>
            </details>
          </div>
        )}
      </div>
    </div>
  );
}
