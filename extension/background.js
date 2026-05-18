/**
 * extension/background.js
 * ========================
 * Background service worker.
 * Calls POST /scan on every navigation completion so results are cached
 * server-side by the time the user opens the popup.
 *
 * Backend URL: http://localhost:8000
 */

const BACKEND_URL = "http://localhost:8000";

// Installed event
chrome.runtime.onInstalled.addListener(() => {
  console.log("[PhishGuard] Extension installed — backend:", BACKEND_URL);
});

// ── Tab listener ─────────────────────────────────────────────────────────
// Pre-scan each page as soon as it fully loads.
// This means the popup result is near-instant because the scan is already done.
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  if (!tab.url?.startsWith("http://") && !tab.url?.startsWith("https://")) return;

  // Skip internal pages and localhost (avoid scanning the dashboard itself)
  const hostname = (() => {
    try { return new URL(tab.url).hostname; } catch (_) { return ""; }
  })();
  if (!hostname || hostname === "localhost" || hostname === "127.0.0.1") return;

  // Fire-and-forget background scan
  fetch(`${BACKEND_URL}/scan`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ url: tab.url }),
  })
    .then(async (res) => {
      if (!res.ok) return;
      const data = await res.json();
      console.log(`[PhishGuard] ${tab.url.slice(0, 60)} → ${data.verdict} (${data.risk_score}%)`);

      // Show a browser notification for high-risk pages
      if (data.verdict === "phishing" || data.risk_score >= 70) {
        chrome.notifications.create({
          type:    "basic",
          iconUrl: "icons/icon48.png",
          title:   "⚠ PhishGuard Alert",
          message: `Phishing detected!\n${tab.url.slice(0, 80)}\nRisk: ${data.risk_score.toFixed(0)}%`,
          priority: 2,
        });
      }
    })
    .catch(() => {
      // Backend not running — silently skip
    });
});
