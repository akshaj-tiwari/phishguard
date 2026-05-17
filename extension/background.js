// background.js
chrome.runtime.onInstalled.addListener(() => {
  console.log('PhishGuard extension installed.');
});

// Listen for tab updates to analyze URLs in the background
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    if (tab.url.startsWith('http://') || tab.url.startsWith('https://')) {
      // Here you would typically make an API call to the FastAPI backend
      // e.g., fetch('http://localhost:8000/analyze', { method: 'POST', body: JSON.stringify({ url: tab.url }) })
      console.log(`Analyzing: ${tab.url}`);
    }
  }
});
