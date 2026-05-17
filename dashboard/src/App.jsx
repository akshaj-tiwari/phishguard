import React, { useState } from 'react';
import { Shield, LayoutDashboard, History, Settings, Bell, Search, FileText } from 'lucide-react';
import './index.css';

import DashboardOverview from './components/DashboardOverview';
import ScanHistory from './components/ScanHistory';

function App() {
  const [activeTab, setActiveTab] = useState('overview');

  return (
    <div className="app-container">
      {/* Sidebar */}
      <aside className="sidebar glass" style={{ width: 'var(--sidebar-width)', padding: '24px', display: 'flex', flexDirection: 'column', zIndex: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '40px' }}>
          <Shield color="var(--primary)" size={32} />
          <h2 style={{ fontSize: '1.5rem', margin: 0, color: 'white' }}>PhishGuard</h2>
        </div>
        
        <nav style={{ display: 'flex', flexDirection: 'column', gap: '8px', flex: 1 }}>
          <NavItem 
            icon={<LayoutDashboard size={20} />} 
            label="Overview" 
            active={activeTab === 'overview'} 
            onClick={() => setActiveTab('overview')} 
          />
          <NavItem 
            icon={<History size={20} />} 
            label="Scan History" 
            active={activeTab === 'history'} 
            onClick={() => setActiveTab('history')} 
          />
          <NavItem 
            icon={<FileText size={20} />} 
            label="Threat Reports" 
            active={activeTab === 'reports'} 
            onClick={() => setActiveTab('reports')} 
          />
        </nav>
        
        <div style={{ marginTop: 'auto' }}>
          <NavItem 
            icon={<Settings size={20} />} 
            label="Settings" 
            active={activeTab === 'settings'} 
            onClick={() => setActiveTab('settings')} 
          />
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        {/* Header */}
        <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
          <div>
            <h1 style={{ fontSize: '1.8rem', margin: '0 0 8px 0' }}>
              {activeTab === 'overview' && 'SOC Dashboard'}
              {activeTab === 'history' && 'URL Scan History'}
              {activeTab === 'reports' && 'Exportable Threat Reports'}
              {activeTab === 'settings' && 'System Settings'}
            </h1>
            <p style={{ color: 'var(--text-muted)', margin: 0 }}>Real-time threat intelligence and analytics.</p>
          </div>
          
          <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
            <div style={{ position: 'relative' }}>
              <Search size={18} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input 
                type="text" 
                placeholder="Search IoCs, URLs, Domains..." 
                style={{ 
                  background: 'var(--bg-card)', 
                  border: '1px solid var(--border-color)', 
                  color: 'white', 
                  padding: '10px 16px 10px 40px', 
                  borderRadius: '20px',
                  width: '250px',
                  outline: 'none'
                }} 
              />
            </div>
            <button style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', position: 'relative' }}>
              <Bell size={24} />
              <span style={{ position: 'absolute', top: 0, right: 0, width: '8px', height: '8px', background: 'var(--danger)', borderRadius: '50%' }}></span>
            </button>
            <div style={{ width: '40px', height: '40px', borderRadius: '50%', background: 'linear-gradient(45deg, var(--primary), #8b5cf6)', marginLeft: '12px' }}></div>
          </div>
        </header>

        {/* Dynamic Content */}
        <div className="animate-fade-in" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          {activeTab === 'overview' && <DashboardOverview />}
          {activeTab === 'history' && <ScanHistory />}
          {activeTab === 'reports' && (
            <div className="card" style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: '16px' }}>
              <FileText size={48} color="var(--text-muted)" />
              <h2 style={{ color: 'var(--text-muted)' }}>Threat Reports</h2>
              <p style={{ color: 'var(--text-muted)' }}>Select scans from history to generate structured IoC reports.</p>
              <button className="btn">Generate New Report</button>
            </div>
          )}
          {activeTab === 'settings' && (
             <div className="card" style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
               <p style={{ color: 'var(--text-muted)' }}>Settings configuration.</p>
             </div>
          )}
        </div>
      </main>
    </div>
  );
}

function NavItem({ icon, label, active, onClick }) {
  return (
    <button 
      onClick={onClick}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        width: '100%',
        padding: '12px 16px',
        background: active ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
        color: active ? 'var(--primary)' : 'var(--text-muted)',
        border: 'none',
        borderRadius: '8px',
        cursor: 'pointer',
        fontSize: '0.95rem',
        fontWeight: active ? '600' : '500',
        transition: 'all 0.2s',
        textAlign: 'left'
      }}
    >
      <div style={{ 
        color: active ? 'var(--primary)' : 'var(--text-muted)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }}>
        {icon}
      </div>
      {label}
      {active && <div style={{ marginLeft: 'auto', width: '4px', height: '4px', borderRadius: '50%', background: 'var(--primary)' }}></div>}
    </button>
  );
}

export default App;
