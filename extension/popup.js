/**
 * extension/popup.js
 * ====================
 * Connected to the real PhishGuard FastAPI backend (POST /scan).
 * Falls back to a lightweight heuristic score if the backend is unreachable.
 *
 * Backend URL: http://localhost:8000
 * Change BACKEND_URL below if you deploy the API elsewhere.
 */

// ── Config ─────────────────────────────────────────────────────────────────
const BACKEND_URL = "http://localhost:8000";

// ── DOM refs ───────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  const currentUrlEl  = document.getElementById("current-url");
  const riskCard      = document.getElementById("risk-card");
  const scoreValue    = document.getElementById("score-value");
  const riskLabel     = document.getElementById("risk-label");
  const domainText    = document.getElementById("domain-text");
  const sslText       = document.getElementById("ssl-text");
  const vtText        = document.getElementById("vt-text");
  const dashboardBtn  = document.getElementById("dashboard-btn");

  // ── Get the active tab URL ──────────────────────────────────────────────
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    const tab = tabs[0];
    const url = tab?.url ?? "";

    // Filter out internal browser pages
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      currentUrlEl.textContent = "No page to analyze";
      domainText.textContent   = "Domain: N/A";
      sslText.textContent      = "SSL: N/A";
      if (vtText) vtText.textContent = "";
      setResult(riskCard, scoreValue, riskLabel, 0, "safe", "N/A");
      return;
    }

    // Show truncated URL
    currentUrlEl.textContent = url.length > 60 ? url.slice(0, 60) + "…" : url;

    try {
      const urlObj = new URL(url);
      domainText.textContent = `Domain: ${urlObj.hostname}`;
      sslText.textContent    = `SSL: ${urlObj.protocol === "https:" ? "Secure ✓" : "Insecure ⚠"}`;
    } catch (_) {
      domainText.textContent = "Domain: —";
      sslText.textContent    = "SSL: —";
    }

    // Show loading state
    setResult(riskCard, scoreValue, riskLabel, null, "loading", "Analyzing…");

    // ── Call the real backend ─────────────────────────────────────────────
    try {
      const response = await fetchWithTimeout(
        `${BACKEND_URL}/scan`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
        },
        8000    // 8 second timeout for the extension
      );

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();

      // data.verdict: "benign" | "suspicious" | "phishing"
      // data.risk_score: 0-100
      const status = data.verdict === "phishing"
        ? "malicious"
        : data.verdict === "suspicious"
          ? "suspicious"
          : "safe";

      const labelMap = { malicious: "Malicious", suspicious: "Suspicious", safe: "Safe" };

      setResult(riskCard, scoreValue, riskLabel, data.risk_score, status, labelMap[status]);

      // Show VirusTotal summary if available
      if (vtText && data.cti?.virustotal) {
        const vt = data.cti.virustotal;
        if (vt.status === "no_api_key") {
          vtText.textContent = "VT: No API key";
        } else if (vt.found && vt.positives > 0) {
          vtText.textContent = `VT: ${vt.positives}/${vt.total} engines flagged`;
          vtText.style.color = "#ef4444";
        } else {
          vtText.textContent = "VT: Clean";
          vtText.style.color = "#10b981";
        }
      }

    } catch (err) {
      console.warn("[PhishGuard] Backend unavailable, using heuristics:", err.message);

      // ── Lightweight heuristic fallback ──────────────────────────────────
      const fallback = heuristicScore(url);
      const status   = fallback >= 70 ? "malicious" : fallback >= 30 ? "suspicious" : "safe";
      const labelMap = { malicious: "Malicious", suspicious: "Suspicious", safe: "Safe" };
      setResult(riskCard, scoreValue, riskLabel, fallback, status, labelMap[status] + " (offline)");
      if (vtText) { vtText.textContent = "Backend offline"; vtText.style.color = "#94a3b8"; }
    }
  });

  // ── Open dashboard ────────────────────────────────────────────────────────
  dashboardBtn.addEventListener("click", () => {
    chrome.tabs.create({ url: "http://localhost:5173" });
  });
});


// ── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Sets the risk card UI state.
 * @param {Element} card
 * @param {Element} scoreEl
 * @param {Element} labelEl
 * @param {number|null} score  - 0-100 or null for loading
 * @param {"safe"|"suspicious"|"malicious"|"loading"} status
 * @param {string} label
 */
function setResult(card, scoreEl, labelEl, score, status, label) {
  card.className  = `risk-card ${status}`;
  scoreEl.textContent = score !== null ? Math.round(score) : "--";
  labelEl.textContent = label;
}

/**
 * fetch() with a hard timeout.
 */
function fetchWithTimeout(url, options, ms) {
  const controller = new AbortController();
  const timer      = setTimeout(() => controller.abort(), ms);
  return fetch(url, { ...options, signal: controller.signal })
    .finally(() => clearTimeout(timer));
}

/**
 * Basic heuristic fallback — used when backend is unreachable.
 * Returns a risk score 0-100.
 */
function heuristicScore(url) {
  let score = 5;
  try {
    const u = new URL(url);
    if (u.protocol !== "https:") score += 20;

    const suspiciousKeywords = [
      "login", "secure", "bank", "account", "verify", "update",
      "confirm", "password", "signin", "credential", "billing",
    ];
    const lower = (u.hostname + u.pathname).toLowerCase();
    if (suspiciousKeywords.some((kw) => lower.includes(kw))) score += 35;

    if (u.hostname.includes("-") && u.hostname.split("-").length > 3) score += 15;
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(u.hostname)) score += 30;

    const suspiciousTlds = [".xyz", ".tk", ".ml", ".cf", ".ga", ".gq", ".top", ".pw", ".cc"];
    if (suspiciousTlds.some((tld) => u.hostname.endsWith(tld))) score += 25;
  } catch (_) {
    score = 50;
  }
  return Math.min(score, 100);
}
