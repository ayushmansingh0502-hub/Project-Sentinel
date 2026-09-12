// Content script - Runs on Gmail pages to analyze emails
console.log("🛡️ Scam Shield content script loaded");

// Configuration
const CONFIG = {
  autoAnalyze: true,
  debounceMs: 1000,
  maxEmailLength: 5000
};

let debounceTimer = null;
let lastAnalysis = null;
let lastEmailData = null;
let lastBannerState = { type: 'pending', message: 'Analyzing email…' };
let observer = null;
let observerTarget = null;

function escapeHtml(value) {
  const div = document.createElement('div');
  div.textContent = String(value ?? '');
  return div.innerHTML;
}

/**
 * Extract email data from Gmail DOM
 */
function extractEmailData() {
  try {
    // Find email content container first
    const emailContainer = getEmailContentContainer();
    
    // Gmail HTML structure (may vary)
    const fromElement = document.querySelector('[data-email]');
    const fromEmail = fromElement?.getAttribute('data-email') || 
                      document.querySelector('[data-tooltip*="@"]')?.textContent || 
                      '';
    
    const fromName = document.querySelector('[email]')?.textContent || 
                     document.querySelector('[data-name]')?.textContent || 
                     '';
    
    const subject = document.querySelector('[data-subject]')?.textContent ||
                    document.title.split(' - ')[0] ||
                    '';
    
    // Extract text ONLY from email container, not entire page
    let messageText = '';
    if (emailContainer) {
      messageText = emailContainer.innerText;
    } else {
      messageText = document.body.innerText;
    }
    
    // Extract links - prioritize email container
    let links = [];
    if (emailContainer) {
      links = Array.from(emailContainer.querySelectorAll('a'))
        .map(a => a.href)
        .filter(href => href.startsWith('http'));
    } else {
      links = Array.from(document.querySelectorAll('a'))
        .map(a => a.href)
        .filter(href => href.startsWith('http'));
    }
    
    return {
      from_email: fromEmail,
      from_name: fromName,
      subject: subject,
      message_text: messageText.substring(0, CONFIG.maxEmailLength),
      links: [...new Set(links)]
    };
  } catch (error) {
    console.error("❌ Error extracting email:", error);
    return null;
  }
}

/**
 * Send email for analysis
 */
async function analyzeCurrentEmail() {
  const emailData = extractEmailData();
  
  console.log("📧 Email data extracted:", emailData);
  
  if (!emailData || !emailData.message_text) {
    console.log("⚠️ No email content found to analyze");
    showPendingBanner("Open an email to analyze");
    return;
  }

  showPendingBanner("Analyzing email…");
  
  console.log("📧 Analyzing email", "Message length:", emailData.message_text.length, "Links found:", emailData.links.length);
  
  // Send to background script
  chrome.runtime.sendMessage(
    {
      action: "analyzeEmail",
      data: emailData
    },
    (response) => {
      if (response.success) {
        console.log("✅ Analysis successful");
        showAnalysisResult(response.data, emailData);
      } else {
        console.error("❌ Analysis failed:", response.error);
        showError(response.error);
      }
    }
  );
}

/**
 * Display analysis results on the page
 */
function showAnalysisResult(analysis, emailData) {
  console.log("📊 Displaying analysis:", analysis);

  lastAnalysis = analysis;
  lastEmailData = emailData;
  lastBannerState = { type: 'analysis', analysis };
  
  // Create banner
  const banner = createAnalysisBanner(analysis);
  
  insertAnalysisBanner(banner);
  
  // Highlight suspicious content ONLY in email body
  if (analysis.is_scam && analysis.extracted_intelligence) {
    console.log("🎯 Email is scam, starting highlighting...");
    console.log("📌 Extracted intelligence:", analysis.extracted_intelligence);
    highlightSuspiciousContent(analysis.extracted_intelligence);
  } else {
    console.log("✅ Email is safe, no highlighting needed");
  }
}

/**
 * Show a pending banner while analysis runs
 */
function showPendingBanner(message) {
  lastBannerState = { type: 'pending', message: message || 'Analyzing email…' };
  const banner = createStatusBanner({
    title: 'Scanning',
    message: lastBannerState.message,
    icon: '⏳',
    color: '#6a4',
    bgColor: '#f2f7ef',
    borderColor: '#6a4'
  });
  insertAnalysisBanner(banner);
}

/**
 * Insert banner into Gmail thread or main content
 */
function insertAnalysisBanner(banner) {
  const emailContainer = document.querySelector('[data-thread-id]');
  if (emailContainer) {
    const existingBanner = emailContainer.querySelector('.scam-shield-banner');
    if (existingBanner) existingBanner.remove();
    emailContainer.insertBefore(banner, emailContainer.firstChild);
    console.log("✅ Banner inserted in thread container");
    return;
  }

  const mainContent = document.querySelector('[role="main"]');
  if (mainContent) {
    const existingBanner = mainContent.querySelector('.scam-shield-banner');
    if (existingBanner) existingBanner.remove();
    mainContent.insertBefore(banner, mainContent.firstChild);
    console.log("✅ Banner inserted in main content");
    return;
  }

  const fixedHost = getOrCreateFixedBannerHost();
  const existingBanner = fixedHost.querySelector('.scam-shield-banner');
  if (existingBanner) existingBanner.remove();
  fixedHost.prepend(banner);
  console.log("✅ Banner inserted in fixed host");
}

/**
 * Ensure banner stays visible when Gmail re-renders the DOM
 */
function ensureBannerVisible() {
  const hasBanner = document.querySelector('.scam-shield-banner');
  if (hasBanner) return;

  const banner = renderBannerFromState();
  if (banner) insertAnalysisBanner(banner);
}

/**
 * Render the banner based on the last known state
 */
function renderBannerFromState() {
  if (lastBannerState.type === 'analysis' && lastBannerState.analysis) {
    return createAnalysisBanner(lastBannerState.analysis);
  }

  if (lastBannerState.type === 'error') {
    return createStatusBanner({
      title: 'Analysis unavailable',
      message: lastBannerState.message || 'Unknown error',
      icon: '⚠️',
      color: '#b67c00',
      bgColor: '#fef3cd',
      borderColor: '#ffc107'
    });
  }

  return createStatusBanner({
    title: 'Scanning',
    message: lastBannerState.message || 'Analyzing email…',
    icon: '⏳',
    color: '#6a4',
    bgColor: '#f2f7ef',
    borderColor: '#6a4'
  });
}

/**
 * Create a simple status banner
 */
function createStatusBanner({ title, message, icon, color, bgColor, borderColor }) {
  const banner = document.createElement('div');
  banner.className = 'scam-shield-banner';
  banner.innerHTML = `
    <div style="
      background: ${bgColor};
      border-left: 4px solid ${borderColor};
      padding: 12px 16px;
      margin: 8px 0;
      border-radius: 4px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 13px;
      line-height: 1.5;
    ">
      <div style="display: flex; gap: 8px; align-items: flex-start;">
        <span style="font-size: 18px; flex-shrink: 0;">${icon}</span>
        <div style="flex: 1;">
          <div style="font-weight: 600; color: ${color}; margin-bottom: 4px;">
            ${escapeHtml(title)}
          </div>
          <div style="color: #555; font-size: 12px;">
            ${escapeHtml(message)}
          </div>
        </div>
      </div>
    </div>
  `;
  return banner;
}

function getOrCreateFixedBannerHost() {
  let host = document.getElementById('scam-shield-fixed-host');
  if (host) return host;

  host = document.createElement('div');
  host.id = 'scam-shield-fixed-host';
  host.style.position = 'fixed';
  host.style.top = '8px';
  host.style.left = '50%';
  host.style.transform = 'translateX(-50%)';
  host.style.zIndex = '2147483647';
  host.style.maxWidth = '780px';
  host.style.width = 'calc(100% - 24px)';
  host.style.pointerEvents = 'auto';

  document.body.appendChild(host);
  return host;
}

/**
 * Create analysis banner element
 */
function createAnalysisBanner(analysis) {
  const banner = document.createElement('div');
  banner.className = 'scam-shield-banner';
  
  const riskLevel = analysis.risk?.risk_level || 'unknown';
  const riskScore = analysis.risk?.risk_score || 0;
  const bgColor = analysis.is_scam ? '#fee' : '#efe';
  const borderColor = analysis.is_scam ? '#c33' : '#3a3';
  const icon = analysis.is_scam ? '⚠️' : '✅';
  
  banner.innerHTML = `
    <div style="
      background: ${bgColor};
      border-left: 4px solid ${borderColor};
      padding: 12px 16px;
      margin: 8px 0;
      border-radius: 4px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 13px;
      line-height: 1.5;
    ">
      <div style="display: flex; gap: 8px; align-items: flex-start;">
        <span style="font-size: 18px; flex-shrink: 0;">${icon}</span>
        <div style="flex: 1;">
          <div style="font-weight: 600; color: ${analysis.is_scam ? '#c33' : '#3a3'}; margin-bottom: 4px;">
            ${analysis.is_scam ? 'Scam Alert' : 'Looks Safe'}
          </div>
          
          ${analysis.reasons && analysis.reasons.length > 0 ? `
            <div style="color: #555; font-size: 12px; margin-bottom: 4px;">
              ${escapeHtml(analysis.reasons.join(' • '))}
            </div>
          ` : ''}
          
          <div style="color: #666; font-size: 12px;">
            Confidence: <strong>${(analysis.confidence * 100).toFixed(0)}%</strong> | 
            Risk: <strong>${riskScore}/100</strong>
          </div>
          
          ${analysis.extracted_intelligence?.upi_ids?.length > 0 ? `
            <div style="color: #c33; font-size: 12px; margin-top: 4px;">
              🚨 Found UPI IDs: ${escapeHtml(analysis.extracted_intelligence.upi_ids.join(', '))}
            </div>
          ` : ''}
          
          ${analysis.extracted_intelligence?.phishing_links?.length > 0 ? `
            <div style="color: #c33; font-size: 12px; margin-top: 4px;">
              🔗 Found suspicious links: ${escapeHtml(analysis.extracted_intelligence.phishing_links.slice(0, 2).join(', '))}
            </div>
          ` : ''}
        </div>
      </div>
    </div>
  `;
  
  return banner;
}

/**
 * Find the email content container
 */
function getEmailContentContainer() {
  // Try various Gmail selectors for email body - from most specific to general
  const selectors = [
    'div[data-message-id]',      // Message container by ID
    '[role="article"]',           // Article role (Gmail new UI)
    'div.aO.T-I-aO',             // Message body wrapper
    '.ii',                        // Message inspection pane (newer Gmail)
    'div[role="main"] .Hs',       // Main content email display
    'div[data-thread-id]',        // Thread container
  ];
  
  let container = null;
  
  for (const selector of selectors) {
    const el = document.querySelector(selector);
    if (el && el.innerText && el.innerText.length > 20) { // Ensure it has substantial text
      console.log("✅ Found email container with selector:", selector, "Text length:", el.innerText.length);
      container = el;
      break;
    }
  }
  
  // If nothing found, try finding the email body by looking for common email patterns
  if (!container) {
    const allDivs = document.querySelectorAll('div');
    for (let div of allDivs) {
      const text = div.innerText;
      // Look for divs with email content patterns (greeting + email patterns)
      if (text && text.includes('Dear') && (text.includes('account') || text.includes('verify') || text.includes('click'))) {
        console.log("✅ Found email container by content pattern");
        container = div;
        break;
      }
    }
  }
  
  // Last resort: look in main content area
  if (!container) {
    const mainContent = document.querySelector('[role="main"]');
    if (mainContent && mainContent.innerText && mainContent.innerText.length > 50) {
      console.log("✅ Using main content area as container");
      container = mainContent;
    }
  }
  
  if (!container) {
    console.warn("⚠️ Could not find email container");
  }
  
  return container;
}

/**
 * Highlight suspicious UPIs, links, etc in email
 */
function highlightSuspiciousContent(intelligence) {
  const emailContainer = getEmailContentContainer();
  console.log("🔎 Highlighting in container:", emailContainer ? "FOUND" : "NOT FOUND");
  
  if (!emailContainer) {
    console.warn("⚠️ Could not find email content container for highlighting");
    return;
  }
  
  // Highlight UPI IDs - only in email container
  if (intelligence.upi_ids && intelligence.upi_ids.length > 0) {
    console.log("💰 Highlighting UPI IDs:", intelligence.upi_ids);
    highlightText(intelligence.upi_ids, '#ffcccc', '#cc3333', emailContainer);
  }
  
  // Highlight phishing links - only in email container
  if (intelligence.phishing_links && intelligence.phishing_links.length > 0) {
    console.log("🔗 Highlighting phishing links:", intelligence.phishing_links);
    const links = emailContainer.querySelectorAll('a');
    console.log("🔎 Found", links.length, "links in email container");
    
    links.forEach(link => {
      if (intelligence.phishing_links.some(phish => link.href.includes(phish))) {
        link.style.backgroundColor = '#ffcccc';
        link.style.color = '#cc3333';
        link.style.fontWeight = 'bold';
        link.style.textDecoration = 'line-through';
        console.log("✅ Highlighted link:", link.href);
      }
    });
  }
}

// Helper function to highlight text ONLY in email container
function highlightText(texts, bgColor, textColor, container) {
  if (!container) {
    console.warn("⚠️ No container for highlighting");
    return;
  }
  
  console.log("🔍 Starting to highlight:", texts, "in container with", container.innerText.length, "chars");
  
  const walker = document.createTreeWalker(
    container,  // Only walk within email container
    NodeFilter.SHOW_TEXT,
    null,
    false
  );
  
  let node;
  const nodesToProcess = [];
  
  // Collect nodes that contain our target text
  while (node = walker.nextNode()) {
    const nodeText = node.textContent.toLowerCase();
    texts.forEach(text => {
      if (nodeText.includes(text.toLowerCase())) {
        nodesToProcess.push({ node, text });
        console.log("📍 Found match:", text, "in node");
      }
    });
  }
  
  console.log("📊 Processing", nodesToProcess.length, "nodes for highlighting");
  
  // Replace nodes with highlighted versions
  const processed = new Set();
  nodesToProcess.forEach(({ node, text }) => {
    if (processed.has(node)) return; // Skip if already processed
    processed.add(node);
    
    try {
      const escapedText = escapeHtml(node.textContent);
      const escapedTarget = escapeHtml(text);
      const regex = new RegExp(`(${escapedTarget.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
      const span = document.createElement('span');
        span.innerHTML = escapedText.replace(regex,
        `<span class="scam-shield-highlight" style="background: ${bgColor}; color: ${textColor}; font-weight: bold; padding: 2px 4px; border-radius: 2px;">$1</span>`
      );
      node.parentNode.replaceChild(span, node);
      console.log("✅ Highlighted:", text);
    } catch (e) {
      console.error("❌ Error highlighting:", text, e);
    }
  });
}

/**
 * Show error message
 */
function showError(errorMsg) {
  lastBannerState = { type: 'error', message: errorMsg || 'Unknown error' };
  const banner = renderBannerFromState();
  if (banner) insertAnalysisBanner(banner);
}

/**
 * Debounced email analysis
 */
function debouncedAnalyze() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(analyzeCurrentEmail, CONFIG.debounceMs);
}

/**
 * Monitor Gmail for new emails
 */
function setupObservers() {
  if (!observer) {
    observer = new MutationObserver(() => {
      if (CONFIG.autoAnalyze) {
        debouncedAnalyze();
      }

      ensureBannerVisible();
      attachObserver();
    });
  }

  attachObserver();

  // Retry attachment while Gmail hydrates
  setInterval(attachObserver, 2000);
}

function attachObserver() {
  const target =
    document.querySelector('[data-view-name="MAIN"]') ||
    document.querySelector('[role="main"]') ||
    document.body;

  if (!target || target === observerTarget || !observer) return;

  if (observerTarget) observer.disconnect();
  observer.observe(target, {
    childList: true,
    subtree: true,
    characterData: true
  });
  observerTarget = target;
  console.log("✅ Gmail observer attached");
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', setupObservers);
} else {
  setupObservers();
}

// Show a banner immediately on load
showPendingBanner('Analyzing email…');

// Kick off an initial analysis
setTimeout(() => {
  if (CONFIG.autoAnalyze) {
    debouncedAnalyze();
  }
}, 500);

// Also analyze when user clicks on an email
document.addEventListener('click', (e) => {
  if (e.target.closest('[data-thread-id]') || e.target.closest('[role="main"]')) {
    debouncedAnalyze();
  }
}, true);

console.log("✅ Scam Shield content script initialized");
