/**
 * dashboard/src/components/ScanHistory.jsx
 * ==========================================
 * Connected to GET /history — real paginated data from the backend.
 * "View" button opens the ThreatReportModal (GET /report/{id}).
 */

import React, { useEffect, useState, useCallback } from "react";
import { Download, Eye, ExternalLink, RefreshCw, Loader2, ShieldAlert, Filter } from "lucide-react";
import { getHistory } from "../api";
import ThreatReportModal from "./ThreatReportModal";

const FILTER_MAP = {
  All:        null,
  Phishing:   "phishing",
  Suspicious: "suspicious",
  Safe:       "benign",
};

const VERDICT_LABEL = {
  phishing:   { label: "Phishing",   cls: "malicious" },
  suspicious: { label: "Suspicious", cls: "suspicious" },
  benign:     { label: "Safe",       cls: "safe"       },
};

export default function ScanHistory({ refreshTrigger }) {
  const [filter, setFilter]     = useState("All");
  const [page, setPage]         = useState(1);
  const [data, setData]         = useState(null);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [modalScanId, setModalScanId] = useState(null);

  const limit = 25;

  const loadHistory = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await getHistory({
        page,
        limit,
        verdict: FILTER_MAP[filter],
      });
      setData(result);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [filter, page]);

  // Reset to page 1 when filter changes
  useEffect(() => { setPage(1); }, [filter]);
  useEffect(() => { loadHistory(); }, [loadHistory, refreshTrigger]);

  function exportCSV() {
    if (!data?.scans?.length) return;
    const header = ["scan_id", "url", "verdict", "risk_score", "timestamp"].join(",");
    const rows = data.scans.map((s) =>
      [s.scan_id, `"${s.url}"`, s.verdict, s.risk_score, s.timestamp].join(",")
    );
    const blob = new Blob([[header, ...rows].join("\n")], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `phishguard_history_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
  }

  const totalPages = data ? Math.ceil(data.total / limit) : 1;

  return (
    <>
      <div className="card" style={{ flex: 1, display: "flex", flexDirection: "column" }}>
        {/* Header */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "24px", flexWrap: "wrap", gap: "12px" }}>
          <div>
            <h3 style={{ margin: 0 }}>Scan History</h3>
            {data && <span style={{ fontSize: "0.82rem", color: "var(--text-muted)" }}>{data.total.toLocaleString()} total records</span>}
          </div>

          <div style={{ display: "flex", gap: "10px", alignItems: "center", flexWrap: "wrap" }}>
            {/* Filter tabs */}
            <div style={{ display: "flex", background: "rgba(255,255,255,0.05)", borderRadius: "8px", padding: "4px" }}>
              {Object.keys(FILTER_MAP).map((f) => (
                <button
                  key={f}
                  id={`history-filter-${f.toLowerCase()}`}
                  onClick={() => setFilter(f)}
                  style={{
                    background: filter === f ? "var(--bg-card-hover)" : "transparent",
                    color: filter === f ? "white" : "var(--text-muted)",
                    border: "none",
                    padding: "6px 12px",
                    borderRadius: "6px",
                    cursor: "pointer",
                    fontSize: "0.85rem",
                    fontWeight: "500",
                    transition: "all 0.2s",
                  }}
                >
                  {f}
                </button>
              ))}
            </div>

            <button
              id="history-refresh-btn"
              onClick={loadHistory}
              style={{ background: "transparent", border: "1px solid var(--border-color)", borderRadius: "8px", padding: "7px 10px", color: "var(--text-muted)", cursor: "pointer", display: "flex", alignItems: "center" }}
            >
              <RefreshCw size={15} />
            </button>

            <button
              id="history-export-btn"
              className="btn outline"
              onClick={exportCSV}
              disabled={!data?.scans?.length}
            >
              <Download size={16} /> Export CSV
            </button>
          </div>
        </div>

        {/* Loading */}
        {loading && (
          <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: "12px", padding: "60px" }}>
            <Loader2 size={32} color="var(--primary)" style={{ animation: "spin 1s linear infinite" }} />
            <span style={{ color: "var(--text-muted)" }}>Loading history…</span>
            <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
          </div>
        )}

        {/* Error */}
        {!loading && error && (
          <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column", gap: "12px", padding: "60px" }}>
            <ShieldAlert size={36} color="var(--danger)" />
            <div style={{ color: "var(--danger)", fontWeight: "600" }}>Failed to load history</div>
            <div style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>{error}</div>
            <button className="btn" onClick={loadHistory}><RefreshCw size={16} /> Retry</button>
          </div>
        )}

        {/* Table */}
        {!loading && !error && data && (
          <>
            <div style={{ overflowX: "auto", flex: 1 }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Scan ID</th>
                    <th>Target URL</th>
                    <th>Verdict</th>
                    <th>Risk Score</th>
                    <th>Time</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {data.scans.length === 0 ? (
                    <tr>
                      <td colSpan={6} style={{ textAlign: "center", color: "var(--text-muted)", padding: "48px" }}>
                        No scans found for the selected filter.
                      </td>
                    </tr>
                  ) : data.scans.map((scan) => {
                    const vc = VERDICT_LABEL[scan.verdict] ?? { label: scan.verdict, cls: "suspicious" };
                    return (
                      <tr key={scan.scan_id}>
                        <td className="mono" style={{ color: "var(--text-muted)", fontSize: "0.8rem" }}>
                          {scan.scan_id.slice(0, 8)}…
                        </td>
                        <td>
                          <div style={{ display: "flex", alignItems: "center", gap: "8px", maxWidth: "300px" }}>
                            <div style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", fontSize: "0.875rem" }}>
                              {scan.url}
                            </div>
                            <a href={scan.url} target="_blank" rel="noopener noreferrer" style={{ color: "var(--text-muted)", flexShrink: 0 }}>
                              <ExternalLink size={13} />
                            </a>
                          </div>
                        </td>
                        <td>
                          <span className={`badge ${vc.cls}`}>{vc.label}</span>
                        </td>
                        <td>
                          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                            <div style={{ width: "60px", height: "4px", background: "rgba(255,255,255,0.1)", borderRadius: "2px", overflow: "hidden" }}>
                              <div style={{
                                height: "100%",
                                width: `${scan.risk_score}%`,
                                background: scan.risk_score >= 70 ? "var(--danger)" : scan.risk_score >= 30 ? "var(--warning)" : "var(--success)",
                                borderRadius: "2px",
                              }} />
                            </div>
                            <span className="mono" style={{ fontSize: "0.85rem" }}>{scan.risk_score.toFixed(0)}%</span>
                          </div>
                        </td>
                        <td style={{ color: "var(--text-muted)", fontSize: "0.85rem", whiteSpace: "nowrap" }}>
                          {new Date(scan.timestamp).toLocaleString()}
                        </td>
                        <td>
                          <button
                            id={`view-report-${scan.scan_id.slice(0, 8)}`}
                            onClick={() => setModalScanId(scan.scan_id)}
                            style={{ background: "transparent", border: "none", color: "var(--primary)", cursor: "pointer", padding: "4px 8px", borderRadius: "6px", display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "0.8rem", fontWeight: "500" }}
                          >
                            <Eye size={15} /> View
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: "12px", marginTop: "20px", paddingTop: "20px", borderTop: "1px solid var(--border-color)" }}>
                <button
                  className="btn outline"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => p - 1)}
                  style={{ padding: "8px 16px", opacity: page <= 1 ? 0.4 : 1 }}
                >
                  ← Prev
                </button>
                <span style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>
                  Page {page} of {totalPages}
                </span>
                <button
                  className="btn outline"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                  style={{ padding: "8px 16px", opacity: page >= totalPages ? 0.4 : 1 }}
                >
                  Next →
                </button>
              </div>
            )}
          </>
        )}
      </div>

      {/* Threat Report Modal */}
      {modalScanId && (
        <ThreatReportModal
          scanId={modalScanId}
          onClose={() => setModalScanId(null)}
        />
      )}
    </>
  );
}
