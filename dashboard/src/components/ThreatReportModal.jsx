/**
 * dashboard/src/components/ThreatReportModal.jsx
 * ================================================
 * Full-screen modal that fetches GET /report/{scan_id}
 * and renders the complete threat report with features, CTI, WHOIS.
 */

import React, { useEffect, useState } from "react";
import {
  X, ShieldX, ShieldCheck, AlertTriangle,
  Eye, Globe, Cpu, BarChart3, Clock, ExternalLink,
  Loader2, Copy, CheckCheck,
} from "lucide-react";
import { getReport } from "../api";

const VERDICT_COLOR = {
  phishing:   "var(--danger)",
  suspicious: "var(--warning)",
  benign:     "var(--success)",
};

export default function ThreatReportModal({ scanId, onClose }) {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]   = useState(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!scanId) return;
    setLoading(true);
    setError(null);
    getReport(scanId)
      .then(setReport)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [scanId]);

  function copyReportJson() {
    navigator.clipboard.writeText(JSON.stringify(report, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const vColor = report ? VERDICT_COLOR[report.verdict] ?? "var(--text-muted)" : "var(--text-muted)";

  return (
    <div
      id="threat-report-modal-overlay"
      style={{
        position: "fixed", inset: 0, zIndex: 1000,
        background: "rgba(0,0,0,0.75)", backdropFilter: "blur(4px)",
        display: "flex", alignItems: "center", justifyContent: "center",
        padding: "24px",
      }}
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        id="threat-report-modal"
        style={{
          width: "100%", maxWidth: "780px", maxHeight: "90vh",
          background: "var(--bg-card)", borderRadius: "20px",
          border: "1px solid var(--border-color)",
          display: "flex", flexDirection: "column",
          overflow: "hidden",
          boxShadow: "0 24px 64px rgba(0,0,0,0.5)",
          animation: "fadeIn 0.25s ease",
        }}
      >
        {/* Modal Header */}
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "20px 28px", borderBottom: "1px solid var(--border-color)",
          flexShrink: 0,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <Eye size={20} color="var(--primary)" />
            <h2 style={{ margin: 0, fontSize: "1.1rem" }}>Threat Report</h2>
            {report && (
              <span style={{
                fontSize: "0.75rem", padding: "3px 10px", borderRadius: "20px",
                background: `rgba(${report.verdict === "phishing" ? "239,68,68" : report.verdict === "suspicious" ? "245,158,11" : "16,185,129"},0.15)`,
                color: vColor, fontWeight: "600", textTransform: "uppercase", letterSpacing: "0.07em",
              }}>
                {report.verdict}
              </span>
            )}
          </div>
          <div style={{ display: "flex", gap: "8px" }}>
            {report && (
              <button
                onClick={copyReportJson}
                style={{ background: "rgba(255,255,255,0.05)", border: "1px solid var(--border-color)", borderRadius: "8px", padding: "8px 12px", color: "var(--text-muted)", cursor: "pointer", display: "flex", alignItems: "center", gap: "6px", fontSize: "0.8rem" }}
              >
                {copied ? <><CheckCheck size={14} color="var(--success)" /> Copied</> : <><Copy size={14} /> Copy JSON</>}
              </button>
            )}
            <button
              id="threat-report-modal-close"
              onClick={onClose}
              style={{ background: "rgba(255,255,255,0.05)", border: "none", borderRadius: "8px", padding: "8px", color: "var(--text-muted)", cursor: "pointer" }}
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Modal Body — scrollable */}
        <div style={{ overflowY: "auto", padding: "28px", display: "flex", flexDirection: "column", gap: "24px" }}>

          {loading && (
            <div style={{ textAlign: "center", padding: "60px" }}>
              <Loader2 size={36} color="var(--primary)" style={{ animation: "spin 1s linear infinite" }} />
              <div style={{ color: "var(--text-muted)", marginTop: "16px" }}>Loading report…</div>
            </div>
          )}

          {error && (
            <div style={{ padding: "24px", textAlign: "center", color: "var(--danger)" }}>
              <AlertTriangle size={32} style={{ marginBottom: "12px" }} />
              <div>{error}</div>
            </div>
          )}

          {report && (
            <>
              {/* URL + Score */}
              <div style={{ display: "flex", gap: "16px", flexWrap: "wrap" }}>
                <div style={{ flex: 1, minWidth: "260px", background: "rgba(0,0,0,0.25)", borderRadius: "12px", padding: "16px 20px" }}>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "8px" }}>
                    Target URL
                  </div>
                  <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.82rem", wordBreak: "break-all", color: "var(--text-main)" }}>
                    {report.url}
                    <a href={report.url} target="_blank" rel="noopener noreferrer" style={{ marginLeft: "8px", color: "var(--text-muted)" }}>
                      <ExternalLink size={12} />
                    </a>
                  </div>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                  <ScoreBox label="Risk Score" value={`${report.risk_score?.toFixed(1)}%`} color={vColor} />
                  <ScoreBox label="Scan Time" value={report.timestamp ? new Date(report.timestamp).toLocaleString() : "—"} small />
                </div>
              </div>

              {/* CTI Results */}
              {(report.cti?.virustotal || report.cti?.urlhaus) && (
                <Section title="Cyber Threat Intelligence" icon={<Globe size={15} />}>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                    {report.cti.virustotal && (
                      <CTIBlock title="VirusTotal" data={report.cti.virustotal} />
                    )}
                    {report.cti.urlhaus && (
                      <CTIBlock title="URLhaus" data={report.cti.urlhaus} urlhaus />
                    )}
                  </div>
                </Section>
              )}

              {/* DNS/WHOIS */}
              {report.whois && (
                <Section title="DNS / WHOIS" icon={<Globe size={15} />}>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "10px" }}>
                    {[
                      { k: "A Records",    v: report.whois.a_records?.join(", ") || "—" },
                      { k: "Domain Age",   v: report.whois.domain_age_days != null ? `${report.whois.domain_age_days} days` : "—" },
                      { k: "Registrar",    v: report.whois.registrar || "—" },
                      { k: "Country",      v: report.whois.country   || "—" },
                      { k: "New Domain",   v: report.whois.is_new_domain ? "⚠ YES" : "No" },
                      { k: "MX Record",    v: report.whois.has_mx_record ? "Yes" : "No" },
                    ].map(({ k, v }) => (
                      <div key={k} style={{ background: "rgba(0,0,0,0.2)", borderRadius: "8px", padding: "10px 14px" }}>
                        <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginBottom: "4px" }}>{k}</div>
                        <div style={{ fontSize: "0.85rem", fontWeight: "600", fontFamily: "'JetBrains Mono', monospace" }}>{v}</div>
                      </div>
                    ))}
                  </div>
                </Section>
              )}

              {/* ML Features */}
              {report.features && Object.keys(report.features).length > 0 && (
                <Section title="Feature Vector (40 signals)" icon={<Cpu size={15} />}>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: "8px" }}>
                    {Object.entries(report.features).map(([k, v]) => (
                      <div key={k} style={{ background: "rgba(0,0,0,0.2)", borderRadius: "8px", padding: "8px 12px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginRight: "8px" }}>{k}</span>
                        <span style={{
                          fontSize: "0.78rem", fontWeight: "700",
                          fontFamily: "'JetBrains Mono', monospace",
                          color: v === 1 || (typeof v === "number" && v > 0.8) ? "var(--warning)" : "var(--text-main)",
                        }}>
                          {typeof v === "number" ? (Number.isInteger(v) ? v : v.toFixed(3)) : String(v)}
                        </span>
                      </div>
                    ))}
                  </div>
                </Section>
              )}
            </>
          )}
        </div>
      </div>

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(16px); } to { opacity: 1; transform: translateY(0); } }
      `}</style>
    </div>
  );
}

// ── Sub-components ─────────────────────────────────────────────────────────

function Section({ title, icon, children }) {
  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "14px", color: "var(--text-muted)", fontSize: "0.78rem", textTransform: "uppercase", letterSpacing: "0.08em" }}>
        {icon}
        {title}
      </div>
      {children}
    </div>
  );
}

function ScoreBox({ label, value, color, small }) {
  return (
    <div style={{ background: "rgba(0,0,0,0.25)", borderRadius: "10px", padding: "12px 18px", textAlign: "center", minWidth: "120px" }}>
      <div style={{ fontSize: small ? "0.85rem" : "1.6rem", fontWeight: "700", color: color || "var(--text-main)" }}>{value}</div>
      <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: "4px" }}>{label}</div>
    </div>
  );
}

function CTIBlock({ title, data, urlhaus }) {
  const isHot = urlhaus ? data.listed : data.positives > 0;
  return (
    <div style={{ background: "rgba(0,0,0,0.2)", borderRadius: "10px", padding: "14px 16px", border: isHot ? "1px solid rgba(239,68,68,0.25)" : "1px solid rgba(255,255,255,0.06)" }}>
      <div style={{ fontWeight: "600", marginBottom: "10px", display: "flex", alignItems: "center", gap: "8px", fontSize: "0.9rem" }}>
        {isHot ? <ShieldX size={14} color="var(--danger)" /> : <ShieldCheck size={14} color="var(--success)" />}
        {title}
      </div>
      {urlhaus ? (
        <>
          <Row k="Listed"   v={data.listed ? "YES ⚠" : "No"} danger={data.listed} />
          <Row k="Status"   v={data.status} />
          <Row k="Threat"   v={data.threat || "—"} />
        </>
      ) : (
        <>
          <Row k="Detections" v={`${data.positives} / ${data.total}`} danger={data.positives > 0} />
          <Row k="Status"     v={data.status} />
        </>
      )}
    </div>
  );
}

function Row({ k, v, danger }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.82rem", marginBottom: "6px" }}>
      <span style={{ color: "var(--text-muted)" }}>{k}</span>
      <span style={{ fontWeight: "600", color: danger ? "var(--danger)" : "var(--text-main)", fontFamily: "'JetBrains Mono', monospace" }}>{v}</span>
    </div>
  );
}
