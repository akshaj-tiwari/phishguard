/**
 * dashboard/src/components/ScannerPanel.jsx
 * ===========================================
 * URL scanner panel — real POST /scan integration.
 * Shows ML risk score, verdict, CTI enrichment, and top features.
 */

import React, { useState } from "react";
import {
  Shield, ShieldAlert, ShieldCheck, ShieldX,
  Search, Loader2, AlertTriangle, CheckCircle2,
  Globe, Lock, Eye, ExternalLink, Zap, BarChart3,
  ChevronRight, X,
} from "lucide-react";
import { scanUrl } from "../api";

// ── Verdict config ─────────────────────────────────────────────────────────
const VERDICT_CONFIG = {
  benign: {
    label: "Safe",
    color: "var(--success)",
    bg: "rgba(16,185,129,0.12)",
    border: "rgba(16,185,129,0.3)",
    icon: <ShieldCheck size={28} />,
    glow: "0 0 40px rgba(16,185,129,0.25)",
  },
  suspicious: {
    label: "Suspicious",
    color: "var(--warning)",
    bg: "rgba(245,158,11,0.12)",
    border: "rgba(245,158,11,0.3)",
    icon: <AlertTriangle size={28} />,
    glow: "0 0 40px rgba(245,158,11,0.25)",
  },
  phishing: {
    label: "Phishing",
    color: "var(--danger)",
    bg: "rgba(239,68,68,0.12)",
    border: "rgba(239,68,68,0.3)",
    icon: <ShieldX size={28} />,
    glow: "0 0 40px rgba(239,68,68,0.35)",
  },
};

export default function ScannerPanel({ onScanComplete }) {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  async function handleScan(e) {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const data = await scanUrl(url.trim());
      setResult(data);
      onScanComplete?.();           // refresh dashboard stats
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function clearResult() {
    setResult(null);
    setError(null);
    setUrl("");
  }

  const cfg = result ? VERDICT_CONFIG[result.verdict] ?? VERDICT_CONFIG.suspicious : null;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>

      {/* Scanner Input Card */}
      <div className="card" style={{ padding: "32px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "24px" }}>
          <div style={{ padding: "10px", background: "rgba(59,130,246,0.15)", borderRadius: "12px" }}>
            <Shield size={22} color="var(--primary)" />
          </div>
          <div>
            <h2 style={{ fontSize: "1.25rem", margin: 0 }}>URL Threat Scanner</h2>
            <p style={{ color: "var(--text-muted)", fontSize: "0.875rem", margin: 0, marginTop: "2px" }}>
              ML-powered phishing detection with CTI enrichment
            </p>
          </div>
        </div>

        <form onSubmit={handleScan} style={{ display: "flex", gap: "12px" }}>
          <div style={{ flex: 1, position: "relative" }}>
            <Globe
              size={18}
              style={{
                position: "absolute", left: "14px", top: "50%",
                transform: "translateY(-50%)", color: "var(--text-muted)", pointerEvents: "none",
              }}
            />
            <input
              id="scanner-url-input"
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/path?query=value"
              disabled={loading}
              style={{
                width: "100%",
                background: "rgba(15,23,42,0.6)",
                border: "1px solid var(--border-color)",
                borderRadius: "10px",
                color: "white",
                padding: "14px 14px 14px 44px",
                fontSize: "0.9rem",
                fontFamily: "'JetBrains Mono', monospace",
                outline: "none",
                transition: "border-color 0.2s",
              }}
              onFocus={(e) => (e.target.style.borderColor = "var(--primary)")}
              onBlur={(e) => (e.target.style.borderColor = "var(--border-color)")}
            />
          </div>
          <button
            id="scanner-submit-btn"
            type="submit"
            className="btn"
            disabled={loading || !url.trim()}
            style={{
              padding: "14px 28px",
              fontSize: "0.95rem",
              minWidth: "140px",
              justifyContent: "center",
              opacity: loading || !url.trim() ? 0.6 : 1,
            }}
          >
            {loading ? (
              <>
                <Loader2 size={18} style={{ animation: "spin 1s linear infinite" }} />
                Scanning...
              </>
            ) : (
              <>
                <Search size={18} />
                Scan URL
              </>
            )}
          </button>
        </form>

        {/* Quick scan tips */}
        <div style={{ display: "flex", gap: "24px", marginTop: "16px", flexWrap: "wrap" }}>
          {["Paste any URL to analyze", "Real-time ML + CTI enrichment", "Results saved to history"].map((tip, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: "6px", color: "var(--text-muted)", fontSize: "0.8rem" }}>
              <ChevronRight size={12} color="var(--primary)" />
              {tip}
            </div>
          ))}
        </div>
      </div>

      {/* Error State */}
      {error && (
        <div className="card" style={{ borderColor: "rgba(239,68,68,0.3)", background: "rgba(239,68,68,0.08)", padding: "20px 24px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <AlertTriangle size={20} color="var(--danger)" />
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: "600", color: "var(--danger)" }}>Scan Failed</div>
              <div style={{ fontSize: "0.875rem", color: "var(--text-muted)", marginTop: "2px" }}>{error}</div>
            </div>
            <button onClick={clearResult} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)" }}>
              <X size={18} />
            </button>
          </div>
        </div>
      )}

      {/* Result Card */}
      {result && cfg && (
        <div
          className="card animate-fade-in"
          style={{ border: `1px solid ${cfg.border}`, background: cfg.bg, boxShadow: cfg.glow }}
        >
          {/* Header */}
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
              <div style={{ color: cfg.color }}>{cfg.icon}</div>
              <div>
                <div style={{ fontSize: "1.5rem", fontWeight: "700", color: cfg.color }}>{cfg.label}</div>
                <div style={{ fontSize: "0.85rem", color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace", marginTop: "2px" }}>
                  {result.url.length > 70 ? result.url.slice(0, 70) + "…" : result.url}
                </div>
              </div>
            </div>

            <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "8px" }}>
              {/* Risk Score Ring */}
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: "2.5rem", fontWeight: "800", color: cfg.color, lineHeight: 1 }}>
                  {result.risk_score.toFixed(0)}
                  <span style={{ fontSize: "1rem", fontWeight: "500" }}>%</span>
                </div>
                <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                  Risk Score
                </div>
              </div>
              <button onClick={clearResult} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)" }}>
                <X size={16} />
              </button>
            </div>
          </div>

          {/* Risk bar */}
          <div style={{ marginBottom: "24px" }}>
            <div style={{ height: "6px", background: "rgba(255,255,255,0.08)", borderRadius: "4px", overflow: "hidden" }}>
              <div
                style={{
                  height: "100%",
                  width: `${result.risk_score}%`,
                  background: cfg.color,
                  borderRadius: "4px",
                  transition: "width 1s ease",
                  boxShadow: `0 0 8px ${cfg.color}`,
                }}
              />
            </div>
          </div>

          {/* Details Grid */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "24px" }}>

            {/* CTI: VirusTotal */}
            {result.cti?.virustotal && (
              <DetailBlock
                title="VirusTotal"
                icon={<Eye size={14} />}
                status={result.cti.virustotal.status}
                lines={[
                  { label: "Detections", value: `${result.cti.virustotal.positives} / ${result.cti.virustotal.total}` },
                  { label: "Status", value: result.cti.virustotal.status },
                ]}
                danger={result.cti.virustotal.positives > 0}
              />
            )}

            {/* CTI: URLhaus */}
            {result.cti?.urlhaus && (
              <DetailBlock
                title="URLhaus"
                icon={<ShieldAlert size={14} />}
                status={result.cti.urlhaus.status}
                lines={[
                  { label: "Listed", value: result.cti.urlhaus.listed ? "YES" : "No" },
                  { label: "Threat", value: result.cti.urlhaus.threat || "—" },
                ]}
                danger={result.cti.urlhaus.listed}
              />
            )}

            {/* DNS Info */}
            {result.whois && (
              <DetailBlock
                title="DNS / Network"
                icon={<Globe size={14} />}
                lines={[
                  { label: "A Records", value: result.whois.a_records?.length > 0 ? result.whois.a_records.slice(0, 2).join(", ") : "—" },
                  { label: "Protocol", value: result.url.startsWith("https") ? "HTTPS ✓" : "HTTP ⚠" },
                ]}
                danger={!result.url.startsWith("https")}
              />
            )}

            {/* Scan Meta */}
            <DetailBlock
              title="Scan Info"
              icon={<Zap size={14} />}
              lines={[
                { label: "Scan ID", value: result.scan_id.slice(0, 8) + "…" },
                { label: "Time", value: new Date(result.timestamp).toLocaleTimeString() },
              ]}
            />
          </div>

          {/* Top ML Features */}
          {result.top_features?.length > 0 && (
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px", color: "var(--text-muted)", fontSize: "0.8rem", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                <BarChart3 size={14} />
                Top ML Signals
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {result.top_features.slice(0, 6).map((f, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                    <div style={{ width: "160px", fontSize: "0.8rem", color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace", flexShrink: 0 }}>
                      {f.feature}
                    </div>
                    <div style={{ flex: 1, height: "4px", background: "rgba(255,255,255,0.07)", borderRadius: "2px", overflow: "hidden" }}>
                      <div style={{
                        height: "100%",
                        width: `${Math.min(f.importance * 1000, 100)}%`,
                        background: "var(--primary)",
                        borderRadius: "2px",
                      }} />
                    </div>
                    <div style={{ width: "50px", textAlign: "right", fontSize: "0.8rem", color: "var(--text-muted)", fontFamily: "'JetBrains Mono', monospace" }}>
                      {f.value}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Loading skeleton */}
      {loading && (
        <div className="card animate-fade-in" style={{ padding: "40px", textAlign: "center" }}>
          <Loader2 size={36} color="var(--primary)" style={{ animation: "spin 1s linear infinite", marginBottom: "16px" }} />
          <div style={{ fontWeight: "600" }}>Analyzing URL…</div>
          <div style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginTop: "8px" }}>
            Running ML model + CTI enrichment
          </div>
        </div>
      )}

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}

// ── Helper sub-component ───────────────────────────────────────────────────
function DetailBlock({ title, icon, lines, danger }) {
  return (
    <div style={{
      background: "rgba(0,0,0,0.2)",
      borderRadius: "10px",
      padding: "14px 16px",
      border: danger ? "1px solid rgba(239,68,68,0.2)" : "1px solid rgba(255,255,255,0.06)",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "10px", color: danger ? "var(--danger)" : "var(--text-muted)", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.08em" }}>
        {icon}
        {title}
      </div>
      {lines.map((l, i) => (
        <div key={i} style={{ display: "flex", justifyContent: "space-between", fontSize: "0.85rem", marginBottom: i < lines.length - 1 ? "4px" : 0 }}>
          <span style={{ color: "var(--text-muted)" }}>{l.label}</span>
          <span style={{ fontWeight: "600", fontFamily: "'JetBrains Mono', monospace", fontSize: "0.8rem" }}>{l.value}</span>
        </div>
      ))}
    </div>
  );
}
