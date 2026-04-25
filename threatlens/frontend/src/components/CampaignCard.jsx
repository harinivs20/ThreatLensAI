import React from 'react';
import './CampaignCard.css';

export default function CampaignCard({ campaign }) {
  if (!campaign || !campaign.name) return (
    <div className="card cc-none">
      <div className="cc-none-icon">🔍</div>
      <div>
        <div className="cc-none-title">No Campaign Match</div>
        <div className="cc-none-sub">Attack fingerprinted and stored. No known campaign correlation found.</div>
      </div>
    </div>
  );
  const orgTypes = campaign.org_types || {};
  return (
    <div className="card cc-match">
      <div className="cc-header">
        <span className="tag tag-amber">⚠️ CAMPAIGN MATCH</span>
        <div style={{display:'flex',alignItems:'center',gap:8}}>
          {campaign.online
            ? <span className="tag tag-green" style={{fontSize:10}}>🌐 {campaign.source||'Live Intel'}</span>
            : <span className="tag tag-blue"  style={{fontSize:10}}>🗄️ Local DB</span>
          }
          <span className="cc-sim">{campaign.similarity}% similarity</span>
        </div>
      </div>
      <div className="cc-name">{campaign.name}</div>
      <div className="cc-desc">{campaign.description}</div>
      <div className="cc-stats">
        <div className="cc-stat"><div className="cc-stat-val">{campaign.total_orgs}</div><div className="cc-stat-key">Orgs Targeted</div></div>
        <div className="cc-stat"><div className="cc-stat-val">{campaign.first_seen}</div><div className="cc-stat-key">First Seen</div></div>
        <div className="cc-stat"><div className="cc-stat-val">{campaign.region}</div><div className="cc-stat-key">Region</div></div>
      </div>
      <div className="cc-orgs-title">Organisations Targeted by This Group</div>
      <div className="cc-orgs">
        {Object.entries(orgTypes).map(([type,count]) => (
          <div key={type} className="cc-org-row">
            <span className="cc-org-type">{type}</span>
            <div className="cc-org-bar-wrap"><div className="cc-org-bar" style={{width:`${Math.min(count/campaign.total_orgs*200,100)}%`}}/></div>
            <span className="cc-org-count">{count}</span>
          </div>
        ))}
      </div>
      <div className="cc-warning">⚠️ Your institution matches the target profile of this attacker group.</div>
      {campaign.source_url && (
        <a href={campaign.source_url} target="_blank" rel="noreferrer" className="cc-source-link">
          🔗 View on {campaign.source || 'Threat Intel Source'}
        </a>
      )}
    </div>
  );
}
