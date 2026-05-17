import React from 'react';
import { PieChart, Pie, Cell, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { ShieldAlert, ShieldCheck, Activity, Globe } from 'lucide-react';

const mockActivityData = [
  { time: '08:00', scans: 120, malicious: 5 },
  { time: '09:00', scans: 250, malicious: 15 },
  { time: '10:00', scans: 380, malicious: 25 },
  { time: '11:00', scans: 420, malicious: 40 },
  { time: '12:00', scans: 310, malicious: 12 },
  { time: '13:00', scans: 280, malicious: 8 },
  { time: '14:00', scans: 450, malicious: 55 },
];

const pieData = [
  { name: 'Safe', value: 850, color: '#10b981' },
  { name: 'Suspicious', value: 120, color: '#f59e0b' },
  { name: 'Malicious', value: 80, color: '#ef4444' },
];

export default function DashboardOverview() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* Top Stats Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '24px' }}>
        <StatCard title="Total Scans (24h)" value="1,050" icon={<Activity size={24} color="var(--primary)" />} trend="+12.5%" trendPositive={true} />
        <StatCard title="Malicious URLs" value="80" icon={<ShieldAlert size={24} color="var(--danger)" />} trend="+5.2%" trendPositive={false} />
        <StatCard title="Safe URLs" value="850" icon={<ShieldCheck size={24} color="var(--success)" />} trend="-1.5%" trendPositive={false} />
        <StatCard title="Unique Domains" value="432" icon={<Globe size={24} color="#8b5cf6" />} trend="+8.1%" trendPositive={true} />
      </div>

      {/* Charts Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '24px' }}>
        
        {/* Activity Area Chart */}
        <div className="card" style={{ height: '400px', display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ marginBottom: '20px' }}>Scanning Activity</h3>
          <div style={{ flex: 1 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={mockActivityData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="var(--primary)" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorMalicious" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--danger)" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="var(--danger)" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis dataKey="time" stroke="var(--text-muted)" tick={{fill: 'var(--text-muted)', fontSize: 12}} axisLine={false} tickLine={false} />
                <YAxis stroke="var(--text-muted)" tick={{fill: 'var(--text-muted)', fontSize: 12}} axisLine={false} tickLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', borderRadius: '8px' }}
                  itemStyle={{ color: '#fff' }}
                />
                <Area type="monotone" dataKey="scans" name="Total Scans" stroke="var(--primary)" strokeWidth={2} fillOpacity={1} fill="url(#colorScans)" />
                <Area type="monotone" dataKey="malicious" name="Malicious" stroke="var(--danger)" strokeWidth={2} fillOpacity={1} fill="url(#colorMalicious)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk Distribution Pie Chart */}
        <div className="card" style={{ height: '400px', display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ marginBottom: '20px' }}>Risk Distribution</h3>
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative' }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={80}
                  outerRadius={110}
                  paddingAngle={5}
                  dataKey="value"
                  stroke="none"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', borderRadius: '8px' }}
                  itemStyle={{ color: '#fff' }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div style={{ position: 'absolute', textAlign: 'center' }}>
              <div style={{ fontSize: '2rem', fontWeight: 'bold' }}>1,050</div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Total Scans</div>
            </div>
          </div>
          
          <div style={{ display: 'flex', justifyContent: 'space-around', marginTop: '16px' }}>
            {pieData.map((item, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: item.color }}></div>
                <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>{item.name}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
      
    </div>
  );
}

function StatCard({ title, value, icon, trend, trendPositive }) {
  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontSize: '0.9rem', color: 'var(--text-muted)', marginBottom: '8px', fontWeight: '500' }}>{title}</div>
          <div style={{ fontSize: '2rem', fontWeight: 'bold' }}>{value}</div>
        </div>
        <div style={{ padding: '12px', backgroundColor: 'rgba(255,255,255,0.03)', borderRadius: '12px' }}>
          {icon}
        </div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.85rem' }}>
        <span style={{ 
          color: trendPositive ? 'var(--success)' : 'var(--danger)',
          background: trendPositive ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)',
          padding: '2px 8px',
          borderRadius: '12px',
          fontWeight: '600'
        }}>
          {trend}
        </span>
        <span style={{ color: 'var(--text-muted)' }}>vs last 24h</span>
      </div>
    </div>
  );
}
