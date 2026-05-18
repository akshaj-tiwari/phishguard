/**
 * dashboard/src/api.js
 * =====================
 * Central API layer — all backend calls go through here.
 * Update API_BASE_URL if your backend runs on a different host/port.
 */

// ── Config ─────────────────────────────────────────────────────────────────
// In dev: FastAPI runs on :8000, React on :5173
// In production: set VITE_API_BASE_URL in your .env file
export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

// ── Generic fetch wrapper ──────────────────────────────────────────────────
async function apiFetch(path, options = {}) {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
  });

  if (!res.ok) {
    const detail = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(detail?.detail || `HTTP ${res.status}`);
  }

  return res.json();
}

// ── Endpoints ──────────────────────────────────────────────────────────────

/**
 * POST /scan
 * Runs the full ML + CTI phishing analysis pipeline.
 * @param {string} url - The URL to scan
 * @returns {Promise<ScanResponse>}
 */
export async function scanUrl(url) {
  return apiFetch("/scan", {
    method: "POST",
    body: JSON.stringify({ url }),
  });
}

/**
 * GET /stats
 * Dashboard aggregate statistics (total scans, counts by verdict, etc.)
 * @returns {Promise<StatsResponse>}
 */
export async function getStats() {
  return apiFetch("/stats");
}

/**
 * GET /history?page=&limit=&verdict=
 * Paginated scan history, optionally filtered by verdict.
 * @param {object} opts
 * @param {number} [opts.page=1]
 * @param {number} [opts.limit=50]
 * @param {string|null} [opts.verdict=null] - "phishing" | "suspicious" | "benign"
 * @returns {Promise<HistoryResponse>}
 */
export async function getHistory({ page = 1, limit = 50, verdict = null } = {}) {
  const params = new URLSearchParams({ page, limit });
  if (verdict) params.set("verdict", verdict);
  return apiFetch(`/history?${params}`);
}

/**
 * GET /report/{scan_id}
 * Full threat report for a single scan (features, CTI, WHOIS, etc.)
 * @param {string} scanId
 * @returns {Promise<ReportResponse>}
 */
export async function getReport(scanId) {
  return apiFetch(`/report/${scanId}`);
}

/**
 * GET /health
 * Backend health check.
 * @returns {Promise<{status: string, service: string}>}
 */
export async function checkHealth() {
  return apiFetch("/health");
}
