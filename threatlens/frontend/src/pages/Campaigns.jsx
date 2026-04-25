import React, { useEffect, useState } from 'react';
import { getCampaigns } from '../api/api.jsx';
import './Campaigns.css';

export default function Campaigns() {
  const [campaigns,    setCampaigns]    = useState([]);
  const [localCount,   setLocalCount]   = useState(0);
  const [onlineCount,  setOnlineCount]  = useState(0);
  const [loading,      setLoading]      = useState(true);
  const [error,        setError]        = useState('');
  const [filter,       setFilter]       = useState('all'); // 'all' | 'local' | 'online'

  useEffect(() => {
    getCampaigns()
      .then(r => {
        setCampaigns(r.data.campaigns || []);
        setLocalCount(r.data.local_count   || 0);
        setOnlineCount(r.data.online_count || 0);
      })
      .catch(() => setError('Could not load campaigns. Is the backend running?'))
      .finally(() => setLoading(false));
  }, []);

  const filtered = campaigns.filter(c => {
    if (filter === 'local')  return !c.online;
    if (filter === 'online') return  c.online;
    return true;
  });

  if (loading) return <div className="camp-loading">⏳ Loading campaigns...</div>;
  if (error)   return <div className="camp-error">⚠️ {error}</div>;

  return (
    <div className="camp-page">
      <div className="camp-hero">
        <h1>🗺️ Campaign Intelligence</h1>
        <p>Phishing campaigns from our local database + live threat intelligence APIs</p>
      </div>

      {/* Stats + filter row */}
      <div className="camp-control-row">
        <div className="camp-count-chips">
          <span className="count-chip total">{campaigns.length} Total</span>
          <span className="count-chip local">🗄️ {localCount} Local</span>
          <span className="count-chip online">🌐 {onlineCount} Online</span>
        </div>
        <div className="camp-filters">
          {['all','local','online'].map(f => (
            <button key={f} className={`filter-btn ${filter===f?'active':''}`}
              onClick={() => setFilter(f)}>
              {f === 'all' ? 'All' : f === 'local' ? '🗄️ Local DB' : '🌐 Live Intel'}
            </button>
          ))}
        </div>
      </div>

      {/* Online lookup note */}
      {onlineCount === 0 && (
        <div className="camp-info-box">
          💡 <strong>Live Threat Intelligence:</strong> When you scan a phishing URL that doesn't match our local database, 
          ThreatLens automatically queries <strong>URLhaus</strong>, <strong>PhishTank</strong>, and <strong>OpenPhish</strong> APIs 
          and saves any matches here. Scan some URLs to populate this list.
        </div>
      )}

      {filtered.length === 0 && (
        <div className="card camp-empty">
          No {filter === 'online' ? 'online-discovered' : filter} campaigns yet.
          {filter === 'online' && ' Scan phishing URLs to discover campaigns from live APIs.'}
        </div>
      )}

      <div className="camp-list">
        {filtered.map(c => (
          <div key={c.id} className={`card camp-card ${c.online ? 'camp-online' : ''}`}>
            <div className="camp-top">
              <div className="camp-main">
                <div className="camp-badges">
                  <span className="camp-id">{c.id}</span>
                  {c.online
                    ? <span className="tag tag-green camp-source-tag">🌐 {c.source || 'Live Intel'}</span>
                    : <span className="tag tag-blue camp-source-tag">🗄️ Local Database</span>
                  }
                </div>
                <div className="camp-name">{c.name}</div>
                <div className="camp-desc">{c.description}</div>
                <div className="camp-meta">
                  {c.first_seen && <span>📅 First: <strong>{c.first_seen}</strong></span>}
                  {c.last_seen  && <span>📅 Last: <strong>{c.last_seen}</strong></span>}
                  {c.region     && <span>📍 <strong>{c.region}</strong></span>}
                  {c.source_url && (
                    <a href={c.source_url} target="_blank" rel="noreferrer"
                      className="camp-source-link">🔗 View Source</a>
                  )}
                </div>
              </div>
              <div className="camp-total-box">
                <div className="camp-total-num">{c.total_orgs}</div>
                <div className="camp-total-lbl">Orgs Targeted</div>
              </div>
            </div>

            {c.org_types && Object.keys(c.org_types).length > 0 && (
              <div className="camp-orgs">
                {Object.entries(c.org_types).map(([type, count]) => (
                  <div key={type} className="camp-org-chip">
                    <span>{type}</span>
                    <strong>{count}</strong>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
