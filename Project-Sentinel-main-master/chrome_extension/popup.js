// Popup script - Handle popup UI events
console.log("📋 Popup initialized");

// Load settings on popup open
document.addEventListener('DOMContentLoaded', () => {
  loadFlaggedStats();
  loadSettings();
  loadApiSettings();
  setupToggleButtons();
  setupApiSettings();
});

/**
 * Load and display flagged intelligence stats
 */
function loadFlaggedStats() {
  chrome.runtime.sendMessage(
    { action: "getFlaggedStats" },
    (response) => {
      if (response.success) {
        document.getElementById('api-warning').style.display = 'none';
        const stats = response.data;
        document.getElementById('stat-upi').textContent = stats.flagged_upi_ids_count || 0;
        document.getElementById('stat-accounts').textContent = stats.flagged_bank_accounts_count || 0;
        document.getElementById('stat-links').textContent = stats.flagged_phishing_links_count || 0;
        document.getElementById('stat-total').textContent = stats.total_flagged || 0;
      } else {
        console.error("Failed to load stats:", response.error);
        if (response.error && response.error.includes("API key is not configured")) {
          document.getElementById('api-warning').style.display = 'block';
        }
        // Show error but don't break the UI
        document.getElementById('stat-total').textContent = "Error";
      }
    }
  );
}

/**
 * Load settings from storage
 */
function loadSettings() {
  chrome.storage.sync.get(['autoAnalyze', 'highlightScams'], (items) => {
    const autoAnalyze = items.autoAnalyze !== false; // default true
    const highlight = items.highlightScams !== false; // default true
    
    setToggleState('toggle-auto-analyze', autoAnalyze);
    setToggleState('toggle-highlight', highlight);
  });
}

function loadApiSettings() {
  chrome.storage.sync.get(['apiBase'], (syncItems) => {
    chrome.storage.local.get(['apiKey'], (localItems) => {
      const baseInput = document.getElementById('api-base');
      const keyInput = document.getElementById('api-key');
      if (baseInput) baseInput.value = syncItems.apiBase || 'http://localhost:8000';
      if (keyInput) keyInput.value = localItems.apiKey || '';

      if (!localItems.apiKey) {
        document.getElementById('api-warning').style.display = 'block';
      }
    });
  });
}

function validateApiBase(urlStr) {
  if (!urlStr || typeof urlStr !== "string") {
    throw new Error("API Base URL is required.");
  }
  const trimmed = urlStr.trim();
  let url;
  try {
    url = new URL(trimmed);
  } catch (err) {
    throw new Error("Invalid URL format.");
  }

  if (url.username || url.password) {
    throw new Error("API base must not contain user credentials.");
  }

  const scheme = url.protocol.toLowerCase();
  const host = url.hostname.toLowerCase();

  const isLocalhost =
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "::1" ||
    host === "[::1]";

  if (scheme === "http:") {
    if (!isLocalhost) {
      throw new Error("HTTP is only allowed for localhost. Remote servers require HTTPS.");
    }
  } else if (scheme !== "https:") {
    throw new Error(`Unsupported URL scheme: ${scheme}. Only HTTPS (and HTTP for localhost) is allowed.`);
  }

  return url.origin;
}

function setupApiSettings() {
  const saveButton = document.getElementById('save-api-settings');
  if (!saveButton) return;

  saveButton.addEventListener('click', () => {
    const rawApiBase = (document.getElementById('api-base')?.value || '').trim();
    const apiKey = (document.getElementById('api-key')?.value || '').trim();
    const status = document.getElementById('api-save-status');

    let apiBase;
    try {
      apiBase = validateApiBase(rawApiBase);
    } catch (err) {
      if (status) {
        status.style.display = 'block';
        status.className = 'alert alert-error';
        status.textContent = err.message;
      }
      return;
    }

    if (!apiKey) {
      if (status) {
        status.style.display = 'block';
        status.className = 'alert alert-error';
        status.textContent = 'API key is required';
      }
      return;
    }

    chrome.storage.local.set({ apiKey }, () => {
      chrome.storage.sync.set({ apiBase }, () => {
        document.getElementById('api-warning').style.display = 'none';
        if (status) {
          status.style.display = 'block';
          status.className = 'alert alert-success';
          status.textContent = 'Settings saved';
        }
        setTimeout(() => {
          if (status) status.style.display = 'none';
        }, 2000);
        loadFlaggedStats();
      });
    });
  });
}

/**
 * Setup toggle button event listeners
 */
function setupToggleButtons() {
  const autoAnalyzeToggle = document.getElementById('toggle-auto-analyze');
  const highlightToggle = document.getElementById('toggle-highlight');
  
  autoAnalyzeToggle.addEventListener('click', () => {
    const isActive = autoAnalyzeToggle.classList.toggle('active');
    chrome.storage.sync.set({ autoAnalyze: isActive });
  });
  
  highlightToggle.addEventListener('click', () => {
    const isActive = highlightToggle.classList.toggle('active');
    chrome.storage.sync.set({ highlightScams: isActive });
  });
}

/**
 * Helper: Set toggle button state
 */
function setToggleState(elementId, isActive) {
  const element = document.getElementById(elementId);
  if (isActive) {
    element.classList.add('active');
  } else {
    element.classList.remove('active');
  }
}

// Auto-refresh stats every 30 seconds
setInterval(loadFlaggedStats, 30000);
