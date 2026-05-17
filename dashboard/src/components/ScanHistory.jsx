import React, { useState } from 'react';
import { Download, Eye, ExternalLink, Filter } from 'lucide-react';

const mockScanHistory = [
  { id: 'SCN-8932', url: 'https://secure-login.paypa1-update.com', domain: 'paypa1-update.com', risk: 'Malicious', score: 98, date: '2 mins ago' },
  { id: 'SCN-8931', url: 'https://github.com/settings/profile', domain: 'github.com', risk: 'Safe', score: 2, date: '15 mins ago' },
  { id: 'SCN-8930', url: 'http://free-netflix-subs.net/claim', domain: 'free-netflix-subs.net', risk: 'Suspicious', score: 65, date: '1 hr ago' },
  { id: 'SCN-8929', url: 'https://mail.google.com/mail/u/0/', domain: 'google.com', risk: 'Safe', score: 1, date: '2 hrs ago' },
  { id: 'SCN-8928', url: 'https://bankofamerica.secure-auth-login.net', domain: 'secure-auth-login.net', risk: 'Malicious', score: 95, date: '3 hrs ago' },
  { id: 'SCN-8927', url: 'https://amazon.com', domain: 'amazon.com', risk: 'Safe', score: 0, date: '4 hrs ago' },
  { id: 'SCN-8926', url: 'http://bit.ly/3x8sK', domain: 'bit.ly', risk: 'Suspicious', score: 55, date: '5 hrs ago' },
];

export default function ScanHistory() {
  const [filter, setFilter] = useState('All');

  const filteredHistory = filter === 'All' 
    ? mockScanHistory 
    : mockScanHistory.filter(scan => scan.risk === filter);

  return (
    <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <h3 style={{ margin: 0 }}>Recent Scans</h3>
        
        <div style={{ display: 'flex', gap: '12px' }}>
          <div style={{ display: 'flex', background: 'rgba(255,255,255,0.05)', borderRadius: '8px', padding: '4px' }}>
            {['All', 'Malicious', 'Suspicious', 'Safe'].map(f => (
              <button 
                key={f}
                onClick={() => setFilter(f)}
                style={{ 
                  background: filter === f ? 'var(--bg-card-hover)' : 'transparent',
                  color: filter === f ? 'white' : 'var(--text-muted)',
                  border: 'none',
                  padding: '6px 12px',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  fontSize: '0.85rem',
                  fontWeight: '500',
                  transition: 'all 0.2s'
                }}
              >
                {f}
              </button>
            ))}
          </div>
          
          <button className="btn outline">
            <Filter size={16} /> Filter
          </button>
          <button className="btn outline">
            <Download size={16} /> Export CSV
          </button>
        </div>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Scan ID</th>
              <th>Target URL</th>
              <th>Domain Info</th>
              <th>Risk Assessment</th>
              <th>Threat Score</th>
              <th>Time</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredHistory.map((scan) => (
              <tr key={scan.id}>
                <td className="mono" style={{ color: 'var(--text-muted)' }}>{scan.id}</td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', maxWidth: '250px' }}>
                    <div style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{scan.url}</div>
                    <a href="#" style={{ color: 'var(--text-muted)' }}><ExternalLink size={14} /></a>
                  </div>
                </td>
                <td>
                  <span style={{ color: 'var(--text-muted)' }}>{scan.domain}</span>
                </td>
                <td>
                  <span className={`badge ${scan.risk.toLowerCase()}`}>
                    {scan.risk}
                  </span>
                </td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div style={{ 
                      width: '40px', 
                      height: '4px', 
                      background: 'rgba(255,255,255,0.1)', 
                      borderRadius: '2px',
                      overflow: 'hidden'
                    }}>
                      <div style={{ 
                        height: '100%', 
                        width: `${scan.score}%`,
                        background: scan.score > 80 ? 'var(--danger)' : scan.score > 40 ? 'var(--warning)' : 'var(--success)'
                      }}></div>
                    </div>
                    <span className="mono">{scan.score}%</span>
                  </div>
                </td>
                <td style={{ color: 'var(--text-muted)' }}>{scan.date}</td>
                <td>
                  <button style={{ background: 'transparent', border: 'none', color: 'var(--primary)', cursor: 'pointer', padding: '4px' }}>
                    <Eye size={18} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      
      {filteredHistory.length === 0 && (
        <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
          No scans match the current filter.
        </div>
      )}
    </div>
  );
}
