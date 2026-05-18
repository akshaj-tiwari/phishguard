/**
 * dashboard/src/components/SettingsPanel.jsx
 * ============================================
 * Settings for API keys and backend configuration.
 * Values are saved to localStorage so they persist across refreshes.
 * The backend reads keys from its own .env file — these settings
 * show the user where to put them.
 */

import React, { useState, useEffect } from "react";
import {
  Key, Server, Shield, CheckCircle2, AlertTriangle,
  Eye, EyeOff, ExternalLink, Save, Loader2,
} from "lucide-react";
import { checkHealth } from "../api";
import { API_BASE_URL } from "../api";

export default function SettingsPanel() {
  const [backendUrl, setBackendUrl] = useState(
    localStorage.getItem("pg_backend_url") || "http://localhost:8000"
  );
  const [vtKey, setVtKey]   = useState(localStorage.getItem("pg_vt_key_hint") || "");
  const [showVt, setShowVt] = useState(false);
  const [saved, setSaved]   = useState(false);
  const [health, setHealth] = useState(null);
  const [checking, setChecking] = useState(false);

  async function testConnection() {
    setChecking(true);
    setHealth(null);
    try {
      const result = await checkHealth();
      setHealth({ ok: true, msg: result.service });
    } catch (e) {
      setHealth({ ok: false, msg: e.message });
    } finally {
      setChecking(false);
    }
  }

  function saveSettings() {
    localStorage.setItem("pg_backend_url", backendUrl);
    localStorage.setItem("pg_vt_key_hint", vtKey);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  useEffect(() => { testConnection(); }, []);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px", maxWidth: "720px" }}>

      {/* Backend Connection */}
      <div className="card">
        <SectionHeader icon={<Server size={18} />} title="Backend Connection" />
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          <div>
            <label style={{ fontSize: "0.82rem", color: "var(--text-muted)", display: "block", marginBottom: "8px" }}>
              API Base URL
            </label>
            <div style={{ display: "flex", gap: "10px" }}>
              <input
                id="settings-backend-url"
                type="text"
                value={backendUrl}
                onChange={(e) => setBackendUrl(e.target.value)}
                style={inputStyle}
              />
              <button
                id="settings-test-connection"
                className="btn outline"
                onClick={testConnection}
                disabled={checking}
                style={{ minWidth: "130px", justifyContent: "center" }}
              >
                {checking ? <Loader2 size={15} style={{ animation: "spin 1s linear infinite" }} /> : null}
                {checking ? "Testing…" : "Test Connection"}
              </button>
            </div>
            <p style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginTop: "6px" }}>
              Current resolved URL: <code style={codeStyle}>{API_BASE_URL}</code>.
              To change it, set <code style={codeStyle}>VITE_API_BASE_URL</code> in <code style={codeStyle}>dashboard/.env</code>.
            </p>
          </div>

          {/* Connection status */}
          {health && (
            <div style={{
              display: "flex", alignItems: "center", gap: "10px",
              padding: "12px 16px", borderRadius: "10px",
              background: health.ok ? "rgba(16,185,129,0.1)" : "rgba(239,68,68,0.1)",
              border: `1px solid ${health.ok ? "rgba(16,185,129,0.3)" : "rgba(239,68,68,0.3)"}`,
            }}>
              {health.ok
                ? <CheckCircle2 size={18} color="var(--success)" />
                : <AlertTriangle size={18} color="var(--danger)" />
              }
              <div>
                <div style={{ fontWeight: "600", fontSize: "0.875rem", color: health.ok ? "var(--success)" : "var(--danger)" }}>
                  {health.ok ? "Connected" : "Connection Failed"}
                </div>
                <div style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>{health.msg}</div>
              </div>
            </div>
          )}

          {!health && !checking && (
            <div style={{ fontSize: "0.82rem", color: "var(--text-muted)" }}>
              Run the backend: <code style={codeStyle}>cd backend && uvicorn main:app --reload --port 8000</code>
            </div>
          )}
        </div>
      </div>

      {/* API Keys */}
      <div className="card">
        <SectionHeader icon={<Key size={18} />} title="API Keys" />
        <div style={{ background: "rgba(245,158,11,0.08)", border: "1px solid rgba(245,158,11,0.2)", borderRadius: "10px", padding: "12px 16px", marginBottom: "20px", display: "flex", alignItems: "flex-start", gap: "10px" }}>
          <AlertTriangle size={16} color="var(--warning)" style={{ flexShrink: 0, marginTop: "2px" }} />
          <p style={{ fontSize: "0.82rem", color: "var(--text-muted)", margin: 0 }}>
            API keys are stored in <strong>backend/.env</strong> (never in the browser).
            The fields below are reminders only — copy your keys into the backend <code style={codeStyle}>.env</code> file.
          </p>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          {/* VirusTotal */}
          <ApiKeyRow
            id="settings-vt-key"
            label="VirusTotal API Key"
            hint="VIRUSTOTAL_API_KEY"
            description="Free at virustotal.com — 4 req/min, 500 req/day"
            link="https://www.virustotal.com/gui/join-us"
            value={vtKey}
            onChange={setVtKey}
            show={showVt}
            onToggleShow={() => setShowVt((v) => !v)}
          />

          {/* PhishTank — info only */}
          <div>
            <label style={{ fontSize: "0.82rem", color: "var(--text-muted)", display: "block", marginBottom: "6px" }}>
              PhishTank API Key <span style={{ opacity: 0.6 }}>(for dataset download, optional)</span>
            </label>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <input
                id="settings-phishtank-key"
                type="text"
                placeholder="PHISHTANK_API_KEY — set in backend/.env"
                disabled
                style={{ ...inputStyle, opacity: 0.5, cursor: "not-allowed" }}
              />
              <a
                href="https://phishtank.com/develop/index.php"
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: "var(--primary)", flexShrink: 0 }}
              >
                <ExternalLink size={16} />
              </a>
            </div>
          </div>

          {/* DATABASE_URL — info only */}
          <div>
            <label style={{ fontSize: "0.82rem", color: "var(--text-muted)", display: "block", marginBottom: "6px" }}>
              Database URL <span style={{ opacity: 0.6 }}>(SQLite by default, PostgreSQL in production)</span>
            </label>
            <input
              id="settings-database-url"
              type="text"
              placeholder="DATABASE_URL — set in backend/.env (leave blank for SQLite)"
              disabled
              style={{ ...inputStyle, width: "100%", opacity: 0.5, cursor: "not-allowed" }}
            />
            <p style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginTop: "6px" }}>
              Example: <code style={codeStyle}>postgresql://user:pass@localhost:5432/phishguard</code>
            </p>
          </div>
        </div>
      </div>

      {/* Backend .env instructions */}
      <div className="card">
        <SectionHeader icon={<Shield size={18} />} title="Backend .env Setup" />
        <p style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginBottom: "16px" }}>
          Create <code style={codeStyle}>backend/.env</code> (copy from <code style={codeStyle}>.env.example</code>) and fill in your keys:
        </p>
        <pre style={{
          background: "rgba(0,0,0,0.35)", borderRadius: "10px", padding: "16px",
          fontSize: "0.82rem", fontFamily: "'JetBrains Mono', monospace",
          color: "#a5f3fc", overflowX: "auto", border: "1px solid rgba(255,255,255,0.06)",
          lineHeight: "1.7",
        }}>{`# backend/.env

# VirusTotal — free key at virustotal.com
VIRUSTOTAL_API_KEY=your_key_here

# Database (leave unset to use SQLite for dev)
# DATABASE_URL=postgresql://user:pass@localhost:5432/phishguard

# PhishTank (optional, for dataset download)
PHISHTANK_API_KEY=your_key_here`}
        </pre>
      </div>

      {/* Save button */}
      <div style={{ display: "flex", justifyContent: "flex-end" }}>
        <button
          id="settings-save-btn"
          className="btn"
          onClick={saveSettings}
          style={{ padding: "12px 28px" }}
        >
          {saved ? <><CheckCircle2 size={16} /> Saved!</> : <><Save size={16} /> Save Notes</>}
        </button>
      </div>

      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}

// ── Sub-components ─────────────────────────────────────────────────────────

function SectionHeader({ icon, title }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "20px" }}>
      <div style={{ padding: "8px", background: "rgba(59,130,246,0.12)", borderRadius: "8px", color: "var(--primary)" }}>
        {icon}
      </div>
      <h3 style={{ margin: 0, fontSize: "1.05rem" }}>{title}</h3>
    </div>
  );
}

function ApiKeyRow({ id, label, hint, description, link, value, onChange, show, onToggleShow }) {
  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px" }}>
        <label style={{ fontSize: "0.82rem", color: "var(--text-muted)" }}>{label}</label>
        {link && (
          <a href={link} target="_blank" rel="noopener noreferrer" style={{ fontSize: "0.78rem", color: "var(--primary)", display: "flex", alignItems: "center", gap: "4px" }}>
            Get free key <ExternalLink size={11} />
          </a>
        )}
      </div>
      <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
        <input
          id={id}
          type={show ? "text" : "password"}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={`${hint}=your_key_here  →  paste into backend/.env`}
          style={{ ...inputStyle, flex: 1 }}
        />
        <button
          onClick={onToggleShow}
          style={{ background: "rgba(255,255,255,0.05)", border: "1px solid var(--border-color)", borderRadius: "8px", padding: "10px", cursor: "pointer", color: "var(--text-muted)" }}
        >
          {show ? <EyeOff size={16} /> : <Eye size={16} />}
        </button>
      </div>
      <p style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "4px" }}>{description}</p>
    </div>
  );
}

const inputStyle = {
  background: "rgba(15,23,42,0.6)",
  border: "1px solid var(--border-color)",
  borderRadius: "8px",
  color: "white",
  padding: "10px 14px",
  fontSize: "0.875rem",
  outline: "none",
  fontFamily: "'JetBrains Mono', monospace",
  width: "100%",
};

const codeStyle = {
  background: "rgba(0,0,0,0.35)",
  padding: "1px 6px",
  borderRadius: "4px",
  fontFamily: "'JetBrains Mono', monospace",
  fontSize: "0.82em",
};
