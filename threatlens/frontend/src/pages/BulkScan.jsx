import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './BulkScan.css';

const API = 'http://localhost:8000';

export default function BulkScan() {
  const [file,       setFile]       = useState(null);
  const [loading,    setLoading]    = useState(false);
  const [result,     setResult]     = useState(null);
  const [error,      setError]      = useState('');
  const [history,    setHistory]    = useState([]);
  const [activeTab,  setActiveTab]  = useState('scan'); // 'scan' | 'history'
  const [loadingHist,setLoadingHist]= useState(false);

  useEffect(() => { loadHistory(); }, []);

  async function loadHistory() {
    setLoadingHist(true);
    try {
      const { data } = await axios.get(`${API}/api/bulk-history?limit=20`);
      setHistory(data.scans || []);
    } catch { /* backend may not be up yet */ }
    finally { setLoadingHist(false); }
  }

  async function handleScan() {
    if (!file) { setError('Please select a file.'); return; }
    setLoading(true); setError(''); setResult(null);
    try {
      const form = new FormData();
      form.append('file', file);
      const { data } = await axios.post(`${API}/api/bulk-scan`, form,
        { headers: { 'Content-Type': 'multipart/form-data' } });
      setResult(data);
      loadHistory(); // refresh history after scan
    } catch (e) {
      setError(e?.response?.data?.detail || 'Bulk scan failed. Is the backend running?');
    } finally { setLoading(false); }
  }

  function downloadCSV(bulkId) {
    window.open(`${API}/api/bulk-scan/${bulkId}/csv`, '_blank');
  }

  async function loadPastScan(bulkId) {
    try {
      const { data } = await axios.get(`${API}/api/bulk-history`);
      // Get full results by re-fetching isn't available directly —
      // we stored them so show what we have
      setActiveTab('scan');
    } catch {}
  }

  const phishingResults = result?.results?.filter(r => r.verdict === 'PHISHING') || [];
  const safeResults     = result?.results?.filter(r => r.verdict === 'SAFE')     || [];
  const errorResults    = result?.results?.filter(r => r.verdict === 'ERROR')    || [];

  return (
    <div className="bulk-page">
      <div className="bulk-hero">
        <h1>📂 Bulk URL Scanner</h1>
        <p>Upload a CSV file with a <code>url</code> column, or a plain text file with one URL per line. Results in under 1 minute.</p>
      </div>

      {/* Tabs */}
      <div className="bulk-tabs">
        <button className={`bulk-tab ${activeTab==='scan'?'active':''}`}
          onClick={()=>setActiveTab('scan')}>🚀 New Scan</button>
        <button className={`bulk-tab ${activeTab==='history'?'active':''}`}
          onClick={()=>{ setActiveTab('history'); loadHistory(); }}>
          🕘 Scan History {history.length>0 && <span className="hist-badge">{history.length}</span>}
        </button>
      </div>

      {/* ── New Scan Tab ── */}
      {activeTab === 'scan' && (
        <div className="bulk-scan-layout">
          <div className="card bulk-input">
            <div className="section-title">Upload File</div>
            <label className="file-zone">
              <input type="file" accept=".csv,.txt"
                onChange={e=>{ setFile(e.target.files[0]); setResult(null); setError(''); }}/>
              <div className="fz-icon">📁</div>
              <div className="fz-text">
                {file ? `✅ ${file.name}` : 'Click to select CSV or TXT file'}
              </div>
              <div className="fz-hint">CSV with <code>url</code> column · or one URL per line · no limit</div>
            </label>

            <div className="bulk-tips">
              <div className="tip-item">⚡ <strong>Fast:</strong> Runs 10 URLs in parallel — 100 URLs takes ~10 seconds</div>
              <div className="tip-item">📄 <strong>CSV format:</strong> Must have a column named <code>url</code></div>
              <div className="tip-item">📝 <strong>TXT format:</strong> One URL per line, no header needed</div>
            </div>

            {error && <div className="scan-error">⚠️ {error}</div>}

            <button className="scan-btn" onClick={handleScan}
              disabled={loading || !file}>
              {loading
                ? <span>⏳ Scanning in parallel... this may take a moment</span>
                : <span>🚀 Run Bulk Scan</span>}
            </button>
          </div>

          {/* Results */}
          {result && (
            <div className="bulk-results fade-up">
              {/* Summary + download */}
              <div className="result-header-row">
                <div className="bulk-summary">
                  <div className="bsum-card total">
                    <div className="bsum-val">{result.total}</div>
                    <div>Total</div>
                  </div>
                  <div className="bsum-card phishing">
                    <div className="bsum-val">{result.phishing}</div>
                    <div>🚨 Phishing</div>
                  </div>
                  <div className="bsum-card safe">
                    <div className="bsum-val">{result.safe}</div>
                    <div>✅ Safe</div>
                  </div>
                  <div className="bsum-card pct">
                    <div className="bsum-val">
                      {result.total > 0 ? Math.round(result.phishing / result.total * 100) : 0}%
                    </div>
                    <div>Phishing Rate</div>
                  </div>
                </div>
                <button className="btn btn-primary download-btn"
                  onClick={() => downloadCSV(result.id)}>
                  ⬇️ Download Results CSV
                </button>
              </div>

              {/* Phishing table */}
              {phishingResults.length > 0 && (
                <div className="card result-table-card">
                  <div className="table-header phishing-header">
                    🚨 Phishing URLs — {phishingResults.length} detected
                  </div>
                  <table className="data-table">
                    <thead><tr><th>#</th><th>URL</th><th>Risk</th><th>Level</th><th>Campaign</th></tr></thead>
                    <tbody>
                      {phishingResults.map((r, i) => (
                        <tr key={i}>
                          <td>{i + 1}</td>
                          <td className="td-url" title={r.url}>{r.url}</td>
                          <td><strong style={{
                            color: r.risk>=80?'#C00000':r.risk>=60?'#EA580C':'#D97706',
                            fontFamily:'var(--mono)'
                          }}>{r.risk}%</strong></td>
                          <td><span className="tag tag-red">{r.threat_level}</span></td>
                          <td className="td-camp">{r.campaign || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* Safe table */}
              {safeResults.length > 0 && (
                <div className="card result-table-card">
                  <div className="table-header safe-header">
                    ✅ Safe URLs — {safeResults.length} clean
                  </div>
                  <table className="data-table">
                    <thead><tr><th>#</th><th>URL</th><th>Risk</th></tr></thead>
                    <tbody>
                      {safeResults.map((r, i) => (
                        <tr key={i}>
                          <td>{i + 1}</td>
                          <td className="td-url">{r.url}</td>
                          <td><strong style={{color:'#166534', fontFamily:'var(--mono)'}}>{r.risk}%</strong></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {errorResults.length > 0 && (
                <div className="card result-table-card">
                  <div className="table-header error-header">
                    ⚠️ Errors — {errorResults.length} could not be scanned
                  </div>
                  <table className="data-table">
                    <thead><tr><th>#</th><th>URL</th></tr></thead>
                    <tbody>
                      {errorResults.map((r, i) => (
                        <tr key={i}><td>{i+1}</td><td className="td-url">{r.url}</td></tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── History Tab ── */}
      {activeTab === 'history' && (
        <div className="card history-card fade-up">
          <div className="section-title-row">
            <span className="section-title" style={{marginBottom:0,borderBottom:'none',paddingBottom:0}}>
              Bulk Scan History
            </span>
            <button className="btn btn-ghost btn-sm" onClick={loadHistory}>↺ Refresh</button>
          </div>

          {loadingHist && <div className="hist-loading">⏳ Loading history...</div>}

          {!loadingHist && history.length === 0 && (
            <div className="hist-empty">No bulk scans yet. Run a scan to see history here.</div>
          )}

          {!loadingHist && history.length > 0 && (
            <table className="data-table" style={{marginTop:14}}>
              <thead>
                <tr>
                  <th>#</th>
                  <th>File</th>
                  <th>Total</th>
                  <th>Phishing</th>
                  <th>Safe</th>
                  <th>Phishing %</th>
                  <th>Date & Time</th>
                  <th>Download</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h, i) => {
                  const pct = h.total > 0 ? Math.round(h.phishing / h.total * 100) : 0;
                  return (
                    <tr key={h.id}>
                      <td>{i + 1}</td>
                      <td style={{fontFamily:'var(--mono)',fontSize:11,maxWidth:160}} title={h.filename}>
                        {h.filename?.length > 22 ? h.filename.slice(0,22)+'…' : h.filename}
                      </td>
                      <td><strong style={{fontFamily:'var(--mono)'}}>{h.total}</strong></td>
                      <td><span className="tag tag-red">{h.phishing}</span></td>
                      <td><span className="tag tag-green">{h.safe}</span></td>
                      <td>
                        <strong style={{
                          color: pct>=50?'#C00000':pct>=20?'#D97706':'#166534',
                          fontFamily:'var(--mono)'
                        }}>{pct}%</strong>
                      </td>
                      <td style={{fontSize:11,color:'var(--gray-600)'}}>
                        {h.created_at ? new Date(h.created_at).toLocaleString('en-IN') : '—'}
                      </td>
                      <td>
                        <button className="btn btn-ghost btn-sm dl-btn"
                          onClick={() => downloadCSV(h.id)}>
                          ⬇️ CSV
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
