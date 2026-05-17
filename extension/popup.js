document.addEventListener('DOMContentLoaded', async () => {
  const currentUrlEl = document.getElementById('current-url');
  const riskCard = document.getElementById('risk-card');
  const scoreValue = document.getElementById('score-value');
  const riskLabel = document.getElementById('risk-label');
  const domainText = document.getElementById('domain-text');
  const sslText = document.getElementById('ssl-text');
  const dashboardBtn = document.getElementById('dashboard-btn');

  // Get current active tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const activeTab = tabs[0];
    const url = activeTab.url;
    
    currentUrlEl.textContent = url;
    
    try {
      const urlObj = new URL(url);
      domainText.textContent = `Domain: ${urlObj.hostname}`;
      sslText.textContent = `SSL: ${urlObj.protocol === 'https:' ? 'Secure' : 'Insecure'}`;
      
      // Simulate ML backend response for now (since we are mocking it)
      analyzeUrlMock(urlObj);
    } catch (e) {
      currentUrlEl.textContent = 'Invalid or internal page';
      domainText.textContent = 'Domain: N/A';
      sslText.textContent = 'SSL: N/A';
    }
  });

  dashboardBtn.addEventListener('click', () => {
    // Open dashboard. Assume it runs on localhost:5173 for dev
    chrome.tabs.create({ url: 'http://localhost:5173' });
  });

  function analyzeUrlMock(urlObj) {
    // Basic heuristics for mock
    let score = Math.floor(Math.random() * 15); // Default low risk 0-15%
    let status = 'safe';
    let label = 'Safe';
    
    if (urlObj.protocol !== 'https:') {
      score += 20;
    }
    
    const suspiciousKeywords = ['login', 'secure', 'bank', 'account', 'verify', 'update'];
    const hasKeyword = suspiciousKeywords.some(keyword => urlObj.hostname.includes(keyword) || urlObj.pathname.includes(keyword));
    
    if (hasKeyword) {
      score += 40;
    }
    
    // Some known bad mock domains
    if (urlObj.hostname.includes('phish') || urlObj.hostname.includes('malware')) {
      score = 95 + Math.floor(Math.random() * 5);
    }
    
    if (score < 30) {
      status = 'safe';
      label = 'Safe';
    } else if (score < 70) {
      status = 'suspicious';
      label = 'Suspicious';
    } else {
      status = 'malicious';
      label = 'Malicious';
    }
    
    // Update UI
    riskCard.className = `risk-card ${status}`;
    scoreValue.textContent = score;
    riskLabel.textContent = label;
  }
});
