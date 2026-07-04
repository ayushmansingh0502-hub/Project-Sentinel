// Background Service Worker - Handles API calls and message routing
const DEFAULT_API_BASE = "http://localhost:8000";

// Store API key securely in extension storage
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.set({
    apiKey: "",
    apiBase: DEFAULT_API_BASE,
    autoAnalyze: true,
    highlightScams: true
  });
  console.log("🛡️ Scam Shield initialized");
});

function getConfig() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(["apiKey", "apiBase"], (items) => {
      resolve({
        apiKey: (items.apiKey || "").trim(),
        apiBase: (items.apiBase || DEFAULT_API_BASE).trim(),
      });
    });
  });
}

// Listen for messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyzeEmail") {
    analyzeEmail(request.data)
      .then(result => {
        console.log("✅ Analysis result:", result);
        sendResponse({ success: true, data: result });
      })
      .catch(error => {
        console.error("❌ Analysis error:", error);
        sendResponse({ success: false, error: error.message });
      });
    return true; // Will respond asynchronously
  }
  
  if (request.action === "getFlaggedStats") {
    getFlaggedStats()
      .then(stats => {
        sendResponse({ success: true, data: stats });
      })
      .catch(error => {
        sendResponse({ success: false, error: error.message });
      });
    return true;
  }
});

/**
 * Analyze email using backend API
 */
async function analyzeEmail(emailData) {
  const { apiKey, apiBase } = await getConfig();
  if (!apiKey) {
    throw new Error("API key is not configured. Open extension popup and set it in Settings.");
  }

  const { from_email, from_name, subject, message_text, links } = emailData;
  
  const payload = {
    from_email: from_email || "unknown@example.com",
    from_name: from_name || "Unknown",
    subject: subject || "",
    message_text: message_text || "",
    links: links || []
  };
  
  console.log("📤 Sending to API:", payload);
  
  const response = await fetch(`${apiBase}/analyze-email`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey
    },
    body: JSON.stringify(payload)
  });
  
  if (!response.ok) {
    throw new Error(`API error: ${response.status} ${response.statusText}`);
  }
  
  const result = await response.json();
  console.log("✅ API Response:", result);
  return result;
}

/**
 * Get flagged intelligence statistics
 */
async function getFlaggedStats() {
  const { apiKey, apiBase } = await getConfig();
  if (!apiKey) {
    throw new Error("API key is not configured. Open extension popup and set it in Settings.");
  }

  const response = await fetch(`${apiBase}/admin/flagged-intelligence`, {
    method: "GET",
    headers: {
      "x-api-key": apiKey
    }
  });
  
  if (!response.ok) {
    throw new Error(`Stats API error: ${response.status}`);
  }
  
  return await response.json();
}

// Log service worker is active
console.log("🔒 Scam Shield background worker loaded");
