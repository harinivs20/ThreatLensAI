import React from 'react';
import { NavLink } from 'react-router-dom';
import './Navbar.css';

const LINKS = [
  { to: '/',          label: '🔍 Scanner'   },
  { to: '/bulk',      label: '📂 Bulk Scan' },
  { to: '/dashboard', label: '📊 Dashboard' },
  { to: '/campaigns', label: '🗺️ Campaigns'  },
];

export default function Navbar() {
  return (
    <nav className="navbar">
      <div className="nb-brand">
        <span className="nb-logo">🛡️</span>
        <div>
          <div className="nb-title">ThreatLens <span>AI</span></div>
          <div className="nb-sub">Phishing Intelligence Platform</div>
        </div>
      </div>
      <div className="nb-links">
        {LINKS.map(l => (
          <NavLink key={l.to} to={l.to} end={l.to==='/'} className={({isActive})=>`nb-link${isActive?' active':''}`}>
            {l.label}
          </NavLink>
        ))}
      </div>
      <div className="nb-status">
        <span className="nb-dot"/> API Ready
      </div>
    </nav>
  );
}
