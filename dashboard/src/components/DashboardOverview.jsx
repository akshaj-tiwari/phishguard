/**
 * dashboard/src/components/DashboardOverview.jsx
 * ================================================
 * Connected to GET /stats — real data from the backend.
 */

import React, { useEffect, useState, useCallback } from "react";
import {
  PieChart, Pie, Cell,
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from "recharts";
import { ShieldAlert, ShieldCheck, Activity, Globe, Loader2, RefreshCw } from "lucide-react";
import { getStats } from "../api";

const PIE_COLORS = {
  benign:     "#10b981",
  suspicious: "#f59e0b",
  phishing:   "#ef4444",
};

export default function DashboardOverview({ refreshTrigger }) {
  const [stats, setStats]     = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  const loadStats = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getStats();
      setStats(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadStats(); }, [loadStats, refreshTrigger]);

  // ── Derived data for charts ──────────────────────────────────────────────
  const pieData = stats
    ? [
        { name: "Safe",       value: stats.benign_count,    color: PIE_COLORS.benign     },
        { name: "Suspicious", value: stats.suspicious_count,color: PIE_COLORS.suspicious },
        { name: "Malicious",  value: stats.phishing_count,  color: PIE_COLORS.phishing   },
      ].filter((d) => d.value > 0)
    : [];

  const totalPie = pieData.reduce((sum, d) => sum + d.value, 0);

  // Top domains bar data
  const topDomains = stats?.top_flagged_domains?.slice(0, 6) || [];

  if (loading) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "300px", flexDirection: "column", gap: "16px" }}>
        <Loader2 size={36} color="var(--primary)" style={{ animation: "spin 1s linear infinite" }} />
        <span style={{ color: "var(--text-muted)" }}>Loading analytics…</span>
        <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card" style={{ textAlign: "center", padding: "40px", borderColor: "rgba(239,68,68,0.3)" }}>
        <ShieldAlert size={36} color="var(--danger)" style={{ marginBottom: "12px" }} />
        <h3 style={{ color: "var(--danger)", marginBottom: "8px" }}>Could not load dashboard stats</h3>
        <p style={{ color: "var(--text-muted)", marginBottom: "20px" }}>{error}</p>
        <p style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginBottom: "20px" }}>
          Make sure the backend is running at <code style={{ background: "rgba(0,0,0,0.3)", padding: "2px 6px", borderRadius: "4px" }}>http://localhost:8000</code>
        </p>
        <button className="btn" onClick={loadStats}>
          <RefreshCw size={16} /> Retry
        </button>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>

      {/* Top Stats Row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "24px" }}>
        <StatCard
          title="Total Scans"
          value={stats?.total_scans?.toLocaleString() ?? "0"}
          icon={<Activity size={24} color="var(--primary)" />}
          sub="All time"
        />
        <StatCard
          title="Phishing Detected"
          value={stats?.phishing_count?.toLocaleString() ?? "0"}
          icon={<ShieldAlert size={24} color="var(--danger)" />}
          sub={stats && stats.total_scans > 0 ? `${((stats.phishing_count / stats.total_scans) * 100).toFixed(1)}% of scans` : "—"}
          danger
        />
        <StatCard
          title="Safe URLs"
          value={stats?.benign_count?.toLocaleString() ?? "0"}
          icon={<ShieldCheck size={24} color="var(--success)" />}
          sub={stats && stats.total_scans > 0 ? `${((stats.benign_count / stats.total_scans) * 100).toFixed(1)}% of scans` : "—"}
          success
        />
        <StatCard
          title="Avg Risk Score"
          value={`${stats?.avg_risk_score?.toFixed(1) ?? "0"}%`}
          icon={<Globe size={24} color="#8b5cf6" />}
          sub="Across all scans"
        />
      </div>

      {/* Charts Row */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px" }}>

        {/* Risk Distribution Donut */}
        <div className="card" style={{ height: "380px", display: "flex", flexDirection: "column" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
            <h3 style={{ margin: 0 }}>Risk Distribution</h3>
            <button
              onClick={loadStats}
              style={{ background: "transparent", border: "none", cursor: "pointer", color: "var(--text-muted)", display: "flex", alignItems: "center", gap: "4px", fontSize: "0.8rem" }}
            >
              <RefreshCw size={13} /> Refresh
            </button>
          </div>
          <div style={{ flex: 1, position: "relative" }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData.length > 0 ? pieData : [{ name: "No data", value: 1, color: "#334155" }]}
                  cx="50%" cy="50%"
                  innerRadius={75} outerRadius={110}
                  paddingAngle={4}
                  dataKey="value"
                  stroke="none"
                >
                  {(pieData.length > 0 ? pieData : [{ color: "#334155" }]).map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: "var(--bg-card)", borderColor: "var(--border-color)", borderRadius: "8px" }}
                  itemStyle={{ color: "#fff" }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div style={{ position: "absolute", top: "50%", left: "50%", transform: "translate(-50%,-50%)", textAlign: "center", pointerEvents: "none" }}>
              <div style={{ fontSize: "2rem", fontWeight: "bold" }}>{totalPie.toLocaleString()}</div>
              <div style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>Total Scans</div>
            </div>
          </div>
          <div style={{ display: "flex", justifyContent: "space-around", marginTop: "12px" }}>
            {[
              { label: "Safe",       color: PIE_COLORS.benign,    v: stats?.benign_count     },
              { label: "Suspicious", color: PIE_COLORS.suspicious, v: stats?.suspicious_count },
              { label: "Malicious",  color: PIE_COLORS.phishing,   v: stats?.phishing_count   },
            ].map((item, i) => (
              <div key={i} style={{ textAlign: "center" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "6px", justifyContent: "center", marginBottom: "4px" }}>
                  <div style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: item.color }} />
                  <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>{item.label}</span>
                </div>
                <div style={{ fontWeight: "700", fontSize: "1.1rem" }}>{item.v?.toLocaleString() ?? 0}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Top Flagged Domains */}
        <div className="card" style={{ height: "380px", display: "flex", flexDirection: "column" }}>
          <h3 style={{ margin: "0 0 20px 0" }}>Top Scanned Domains</h3>
          {topDomains.length === 0 ? (
            <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: "0.9rem" }}>
              No data yet — scan some URLs to see domains here.
            </div>
          ) : (
            <div style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: "10px" }}>
              {topDomains.map((d, i) => {
                const maxCount = topDomains[0]?.count || 1;
                return (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                    <div style={{ width: "20px", textAlign: "right", color: "var(--text-muted)", fontSize: "0.8rem" }}>#{i + 1}</div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: "0.85rem", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", marginBottom: "4px", fontFamily: "'JetBrains Mono', monospace" }}>
                        {d.domain}
                      </div>
                      <div style={{ height: "4px", background: "rgba(255,255,255,0.07)", borderRadius: "2px", overflow: "hidden" }}>
                        <div style={{ height: "100%", width: `${(d.count / maxCount) * 100}%`, background: "var(--primary)", borderRadius: "2px" }} />
                      </div>
                    </div>
                    <div style={{ fontSize: "0.85rem", fontWeight: "600", color: "var(--text-muted)", width: "30px", textAlign: "right" }}>{d.count}</div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Stat Card ──────────────────────────────────────────────────────────────
function StatCard({ title, value, icon, sub, danger, success }) {
  return (
    <div className="card" style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div style={{ fontSize: "0.85rem", color: "var(--text-muted)", marginBottom: "8px", fontWeight: "500" }}>{title}</div>
          <div style={{
            fontSize: "2rem", fontWeight: "bold",
            color: danger ? "var(--danger)" : success ? "var(--success)" : "var(--text-main)",
          }}>
            {value}
          </div>
        </div>
        <div style={{ padding: "12px", backgroundColor: "rgba(255,255,255,0.03)", borderRadius: "12px" }}>
          {icon}
        </div>
      </div>
      <div style={{ fontSize: "0.82rem", color: "var(--text-muted)" }}>{sub}</div>
    </div>
  );
}
