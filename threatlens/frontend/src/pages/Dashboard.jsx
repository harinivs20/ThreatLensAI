import React, { useEffect, useState } from 'react';
import { getHistory, getStats } from '../api/api.jsx';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid } from 'recharts';
import './Dashboard.css';

const LEVEL_COL = { CRITICAL:'#C00000', HIGH:'#EA580C', MEDIUM:'#D97706', LOW:'#2563eb', NONE:'#166534' };

export default function Dashboard() {
  const [stats,   setStats]   = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState('');

  useEffect(()=>{
    Promise.all([getStats(), getHistory(20)])
      .then(([s,h])=>{ setStats(s.data); setHistory(h.data.scans||[]); })
      .catch(()=>setError('Could not load data. Is the backend running on port 8000?'))
      .finally(()=>setLoading(false));
  },[]);

  if (loading) return <div className="dash-loading">⏳ Loading dashboard...</div>;
  if (error)   return <div className="dash-error">⚠️ {error}</div>;

  const chartData = [
    { name:'PHISHING', value: stats?.phishing_found||0, fill:'#C00000' },
    { name:'SAFE',     value: stats?.safe_found||0,     fill:'#166534' },
  ];

  return (
    <div className="dash-page">
      {/* Stat cards */}
      <div className="stat-grid">
        {[
          { label:'🔍 Total Scanned',  val:stats?.total_scanned  ||0, col:'#2563eb' },
          { label:'🚨 Phishing Found', val:stats?.phishing_found ||0, col:'#C00000' },
          { label:'✅ Safe',           val:stats?.safe_found     ||0, col:'#166534' },
          { label:'🗺️ Campaigns Seen', val:stats?.campaigns_seen ||0, col:'#D97706' },
        ].map(s=>(
          <div key={s.label} className="card stat-card" style={{borderTopColor:s.col}}>
            <div className="stat-val" style={{color:s.col}}>{s.val}</div>
            <div className="stat-lbl">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="dash-grid">
        {/* Chart */}
        <div className="card dash-card">
          <div className="section-title">Scan Breakdown</div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={chartData} margin={{top:10,right:10,left:-20,bottom:0}}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0"/>
              <XAxis dataKey="name" tick={{fontSize:11,fill:'#64748b'}} axisLine={false} tickLine={false}/>
              <YAxis tick={{fontSize:11,fill:'#64748b'}} axisLine={false} tickLine={false} allowDecimals={false}/>
              <Tooltip contentStyle={{borderRadius:8,fontSize:12,border:'1px solid #e2e8f0'}}/>
              <Bar dataKey="value" radius={[6,6,0,0]}>
                {chartData.map((d,i)=><Cell key={i} fill={d.fill}/>)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Recent scans */}
        <div className="card dash-card">
          <div className="section-title-row">
            <span className="section-title" style={{marginBottom:0,borderBottom:'none',paddingBottom:0}}>Recent Scans</span>
            <button className="btn btn-ghost btn-sm"
              onClick={()=>window.open('http://localhost:8000/api/export/csv','_blank')}>
              ⬇️ Export CSV
            </button>
          </div>
          {history.length===0
            ? <div className="dash-empty">No scans yet. Go to Scanner to start.</div>
            : (
              <table className="data-table" style={{marginTop:12}}>
                <thead><tr><th>#</th><th>Input</th><th>Type</th><th>Verdict</th><th>Risk</th><th>Campaign</th></tr></thead>
                <tbody>
                  {history.map((h,i)=>(
                    <tr key={h.id||i}>
                      <td>{i+1}</td>
                      <td style={{fontFamily:'var(--mono)',fontSize:11,maxWidth:200}} title={h.input_value}>
                        {h.input_value?.length>40?h.input_value.slice(0,40)+'…':h.input_value}
                      </td>
                      <td><span className={`tag ${h.input_type==='url'?'tag-blue':'tag-purple'}`}>{h.input_type?.toUpperCase()}</span></td>
                      <td><span className={`tag ${h.verdict==='PHISHING'?'tag-red':'tag-green'}`}>{h.verdict}</span></td>
                      <td><strong style={{color:LEVEL_COL[h.threat_level]||'#64748b',fontFamily:'var(--mono)',fontSize:12}}>{h.overall_risk??'—'}</strong></td>
                      <td style={{fontSize:11,color:'var(--gray-600)',maxWidth:130}}>{h.campaign_name||h.campaign||'—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          }
        </div>
      </div>
    </div>
  );
}
