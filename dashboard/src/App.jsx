import React, { useState, useCallback } from "react";
import {
  Shield, LayoutDashboard, History, Settings,
  Bell, Search, FileText, ScanLine,
} from "lucide-react";
import "./index.css";

import DashboardOverview  from "./components/DashboardOverview";
import ScanHistory        from "./components/ScanHistory";
import ScannerPanel       from "./components/ScannerPanel";
import SettingsPanel      from "./components/SettingsPanel";
import { checkHealth }    from "./api";

// ── API_BASE_URL is defined in src/api.js and read from VITE_API_BASE_URL ──

function App() {
  const [activeTab, setActiveTab]         = useState("overview");
  const [refreshCounter, setRefreshCounter] = useState(0);

  // Called by ScannerPanel after a successful scan to refresh stats + history
  const handleScanComplete = useCallback(() => {
    setRefreshCounter((c) => c + 1);
  }, []);

  return (
    <div className="app-container">
      {/* Sidebar */}
      <aside
        className="sidebar glass"
        style={{ width: "var(--sidebar-width)", padding: "24px", display: "flex", flexDirection: "column", zIndex: 10 }}
      >
        {/* Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "40px" }}>
          <Shield color="var(--primary)" size={32} />
          <div>
            <h2 style={{ fontSize: "1.3rem", margin: 0, color: "white" }}>PhishGuard</h2>
            <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", letterSpacing: "0.06em" }}>ML Threat Intel</div>
          </div>
        </div>

        <nav style={{ display: "flex", flexDirection: "column", gap: "6px", flex: 1 }}>
          <NavItem
            id="nav-overview"
            icon={<LayoutDashboard size={19} />}
            label="Overview"
            active={activeTab === "overview"}
            onClick={() => setActiveTab("overview")}
          />
          <NavItem
            id="nav-scanner"
            icon={<ScanLine size={19} />}
            label="URL Scanner"
            active={activeTab === "scanner"}
            onClick={() => setActiveTab("scanner")}
            accent
          />
          <NavItem
            id="nav-history"
            icon={<History size={19} />}
            label="Scan History"
            active={activeTab === "history"}
            onClick={() => setActiveTab("history")}
          />
          <NavItem
            id="nav-reports"
            icon={<FileText size={19} />}
            label="Threat Reports"
            active={activeTab === "reports"}
            onClick={() => setActiveTab("reports")}
          />
        </nav>

        <div style={{ marginTop: "auto", borderTop: "1px solid var(--border-color)", paddingTop: "16px" }}>
          <NavItem
            id="nav-settings"
            icon={<Settings size={19} />}
            label="Settings"
            active={activeTab === "settings"}
            onClick={() => setActiveTab("settings")}
          />
          {/* Backend status indicator */}
          <BackendStatus />
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        {/* Header */}
        <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "32px" }}>
          <div>
            <h1 style={{ fontSize: "1.8rem", margin: "0 0 4px 0" }}>
              {activeTab === "overview" && "SOC Dashboard"}
              {activeTab === "scanner"  && "URL Scanner"}
              {activeTab === "history"  && "Scan History"}
              {activeTab === "reports"  && "Threat Reports"}
              {activeTab === "settings" && "Settings"}
            </h1>
            <p style={{ color: "var(--text-muted)", margin: 0, fontSize: "0.9rem" }}>
              {activeTab === "overview" && "Real-time threat intelligence and analytics"}
              {activeTab === "scanner"  && "Analyze any URL with ML + Cyber Threat Intelligence"}
              {activeTab === "history"  && "Full log of all scanned URLs"}
              {activeTab === "reports"  && "Detailed per-scan threat reports"}
              {activeTab === "settings" && "Configure API keys and backend connection"}
            </p>
          </div>

          <div style={{ display: "flex", gap: "16px", alignItems: "center" }}>
            {/* Global URL search — switches to scanner */}
            <div style={{ position: "relative" }}>
              <Search
                size={16}
                style={{ position: "absolute", left: "12px", top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)" }}
              />
              <input
                id="header-url-search"
                type="text"
                placeholder="Paste a URL to scan…"
                style={{
                  background: "var(--bg-card)",
                  border: "1px solid var(--border-color)",
                  color: "white",
                  padding: "10px 16px 10px 36px",
                  borderRadius: "20px",
                  width: "240px",
                  outline: "none",
                  fontSize: "0.875rem",
                }}
                onFocus={() => setActiveTab("scanner")}
              />
            </div>
            <button style={{ background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer", position: "relative" }}>
              <Bell size={22} />
              {/* Show badge only if we have scans */}
              {refreshCounter > 0 && (
                <span style={{ position: "absolute", top: 0, right: 0, width: "8px", height: "8px", background: "var(--primary)", borderRadius: "50%" }} />
              )}
            </button>
            <div style={{ width: "36px", height: "36px", borderRadius: "50%", background: "linear-gradient(45deg, var(--primary), #8b5cf6)" }} />
          </div>
        </header>

        {/* Dynamic Content */}
        <div className="animate-fade-in" key={activeTab} style={{ flex: 1, display: "flex", flexDirection: "column" }}>
          {activeTab === "overview" && (
            <DashboardOverview refreshTrigger={refreshCounter} />
          )}
          {activeTab === "scanner" && (
            <ScannerPanel onScanComplete={handleScanComplete} />
          )}
          {activeTab === "history" && (
            <ScanHistory refreshTrigger={refreshCounter} />
          )}
          {activeTab === "reports" && (
            <div className="card" style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: "16px" }}>
              <FileText size={48} color="var(--text-muted)" />
              <h2 style={{ color: "var(--text-muted)" }}>Threat Reports</h2>
              <p style={{ color: "var(--text-muted)" }}>
                Click <strong>View</strong> on any scan in History to open its full threat report.
              </p>
              <button className="btn" onClick={() => setActiveTab("history")}>
                Go to Scan History
              </button>
            </div>
          )}
          {activeTab === "settings" && <SettingsPanel />}
        </div>
      </main>
    </div>
  );
}

// ── NavItem ────────────────────────────────────────────────────────────────
function NavItem({ id, icon, label, active, onClick, accent }) {
  return (
    <button
      id={id}
      onClick={onClick}
      style={{
        display: "flex",
        alignItems: "center",
        gap: "12px",
        width: "100%",
        padding: "11px 16px",
        background: active
          ? accent
            ? "rgba(59,130,246,0.2)"
            : "rgba(59,130,246,0.12)"
          : "transparent",
        color: active ? (accent ? "var(--primary)" : "var(--primary)") : "var(--text-muted)",
        border: active && accent ? "1px solid rgba(59,130,246,0.3)" : "none",
        borderRadius: "10px",
        cursor: "pointer",
        fontSize: "0.9rem",
        fontWeight: active ? "600" : "500",
        transition: "all 0.2s",
        textAlign: "left",
      }}
    >
      <div style={{ color: active ? "var(--primary)" : "var(--text-muted)", display: "flex", alignItems: "center" }}>
        {icon}
      </div>
      {label}
      {active && (
        <div style={{ marginLeft: "auto", width: "6px", height: "6px", borderRadius: "50%", background: "var(--primary)" }} />
      )}
    </button>
  );
}

// ── Backend Status ─────────────────────────────────────────────────────────
function BackendStatus() {
  const [online, setOnline] = React.useState(null);

  React.useEffect(() => {
    checkHealth()
      .then(() => setOnline(true))
      .catch(() => setOnline(false));
  }, []);

  return (
    <div style={{ display: "flex", alignItems: "center", gap: "8px", padding: "12px 16px", marginTop: "8px", background: "rgba(0,0,0,0.2)", borderRadius: "10px" }}>
      <div style={{
        width: "8px", height: "8px", borderRadius: "50%",
        background: online === null ? "#94a3b8" : online ? "var(--success)" : "var(--danger)",
        boxShadow: online ? "0 0 6px var(--success)" : "none",
      }} />
      <div>
        <div style={{ fontSize: "0.78rem", fontWeight: "600", color: "var(--text-main)" }}>Backend API</div>
        <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>
          {online === null ? "Connecting…" : online ? "Online" : "Offline — start uvicorn"}
        </div>
      </div>
    </div>
  );
}

export default App;
