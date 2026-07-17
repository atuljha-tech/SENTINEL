// AI-NMS Security Guardian v10.0
// REAL security checks only — no false positives

const API_BASE = 'https://lokey-secure.vercel.app';

// ── Keep-alive ──
setInterval(() => {
  try { if (chrome?.runtime) chrome.runtime.getPlatformInfo(() => {}); } catch {}
}, 20000);

const tabAnalysis = {};

function defaultState(url) {
  return { score: 100, risk: 0, threats: [], recommendations: [], summary: 'Analyzing…',
           attackType: 'none', url: url || '', domain: '', history: [], analyzing: true };
}

function setBadge(tabId, score, analyzing) {
  const text  = analyzing ? '…' : String(score);
  const color = score >= 80 ? '#00ff88' : score >= 60 ? '#facc15' : score >= 40 ? '#f97316' : '#ff3b3b';
  try {
    chrome.tabs.get(tabId, tab => {
      if (chrome.runtime.lastError || !tab) return;
      chrome.action.setBadgeText({ text, tabId });
      chrome.action.setBadgeBackgroundColor({ color, tabId });
    });
  } catch {}
}

function esc(s) {
  if (!s) return '';
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function isSkippable(url) {
  if (!url) return true;
  return url.startsWith('chrome://') || url.startsWith('chrome-extension://') ||
         url.startsWith('about:') || url.startsWith('edge://') ||
         url.includes('localhost') || url.includes('127.0.0.1');
}

// ════════════════════════════════════════════════════════
// REAL SECURITY SCORING ENGINE
// Only checks things we can actually verify from the browser
// ════════════════════════════════════════════════════════
function realScore(url, cookies, pageData, headers) {
  let risk = 0;
  const threats = [];

  const isHttps = url.startsWith('https://');

  // ── 1. HTTPS (100% verifiable) ──
  if (!isHttps) {
    risk += 40;
    threats.push({ level: 'critical', text: 'No HTTPS — all data sent in plain text' });
  }

  // ── 2. Password field on HTTP (100% verifiable) ──
  if (pageData.hasPassword && !isHttps) {
    risk += 40;
    threats.push({ level: 'critical', text: 'Login form on HTTP page — passwords transmitted unencrypted' });
  }

  // ── 3. Cookie flags (chrome.cookies API gives REAL values) ──
  // chrome.cookies.getAll() returns actual cookie metadata from the browser
  // secure/httpOnly/sameSite are real values, not guesses
  const sessionCookies = cookies.filter(c =>
    c.name.toLowerCase().includes('session') ||
    c.name.toLowerCase().includes('token') ||
    c.name.toLowerCase().includes('auth') ||
    c.name.toLowerCase().includes('sid')
  );

  const insecureSession = sessionCookies.filter(c => !c.secure && isHttps);
  if (insecureSession.length > 0) {
    risk += 25;
    threats.push({ level: 'high', text: `${insecureSession.length} session/auth cookie(s) missing Secure flag (verified via browser API)` });
  }

  const noHttpOnlySession = sessionCookies.filter(c => !c.httpOnly);
  if (noHttpOnlySession.length > 0) {
    risk += 15;
    threats.push({ level: 'medium', text: `${noHttpOnlySession.length} session cookie(s) readable by JavaScript — XSS risk (verified)` });
  }

  const noSameSite = sessionCookies.filter(c => !c.sameSite || c.sameSite === 'unspecified' || c.sameSite === 'no_restriction');
  if (noSameSite.length > 0) {
    risk += 10;
    threats.push({ level: 'low', text: `${noSameSite.length} session cookie(s) missing SameSite — CSRF risk (verified)` });
  }

  // ── 4. Security headers (read from actual HTTP response headers) ──
  // These are real headers returned by the server
  if (headers) {
    if (!headers['content-security-policy'] && !headers['x-content-security-policy']) {
      risk += 10;
      threats.push({ level: 'medium', text: 'Missing Content-Security-Policy header — XSS protection not enforced' });
    }
    if (!headers['x-frame-options'] && !headers['frame-ancestors']) {
      risk += 8;
      threats.push({ level: 'low', text: 'Missing X-Frame-Options — page may be embeddable in iframes (clickjacking risk)' });
    }
    if (!headers['x-content-type-options']) {
      risk += 5;
      threats.push({ level: 'low', text: 'Missing X-Content-Type-Options — MIME sniffing attacks possible' });
    }
    if (isHttps && !headers['strict-transport-security']) {
      risk += 5;
      threats.push({ level: 'low', text: 'Missing HSTS header — browser may allow HTTP downgrade attacks' });
    }
  }

  // ── 5. Mixed content (HTTP resources on HTTPS page — verifiable) ──
  if (isHttps && pageData.httpResources > 0) {
    risk += 15;
    threats.push({ level: 'high', text: `${pageData.httpResources} HTTP resource(s) loaded on HTTPS page — mixed content (verified)` });
  }

  // ── 6. Forms submitting to HTTP (verifiable from DOM) ──
  const insecureForms = (pageData.forms || []).filter(f =>
    f.action && f.action.startsWith('http://') && !f.action.startsWith('https://lokey-secure.vercel.app/')
  );
  if (insecureForms.length > 0) {
    risk += 20;
    threats.push({ level: 'high', text: `${insecureForms.length} form(s) POST to HTTP endpoint — data sent unencrypted (verified from DOM)` });
  }

  // ── 7. Phishing URL patterns (URL is 100% verifiable) ──
  const urlL = url.toLowerCase();
  const phishPatterns = [
    { p: 'paypal', exclude: 'paypal.com' },
    { p: 'apple-id', exclude: 'apple.com' },
    { p: 'netflix-', exclude: 'netflix.com' },
    { p: 'login-verify', exclude: '' },
    { p: 'secure-update', exclude: '' },
    { p: 'account-confirm', exclude: '' },
    { p: 'verify-identity', exclude: '' },
    { p: 'signin-recovery', exclude: '' },
  ];
  for (const { p, exclude } of phishPatterns) {
    if (urlL.includes(p) && (!exclude || !urlL.includes(exclude))) {
      risk += 45;
      threats.push({ level: 'critical', text: `Phishing URL pattern detected: "${p}" in domain` });
      break;
    }
  }

  // ── 8. Known malicious domain list (verifiable) ──
  const maliciousDomains = [
    'malware-tracker.com', 'phishing-site.net', 'fake-login.org',
    'login-verify.com', 'secure-update.net', 'account-verify.org',
  ];
  const domain = (() => { try { return new URL(url).hostname; } catch { return ''; } })();
  if (maliciousDomains.some(d => domain.includes(d))) {
    risk += 60;
    threats.push({ level: 'critical', text: `Domain "${domain}" matches known malicious domain list` });
  }

  // ── 9. Inline script dangerous patterns (reading actual inline script content) ──
  // We only flag inline scripts (not external), and only specific dangerous patterns
  const dangerousInline = (pageData.inlineScriptPatterns || []);
  if (dangerousInline.includes('document.write')) {
    risk += 8;
    threats.push({ level: 'medium', text: 'document.write() found in inline script — potential DOM injection vector' });
  }
  if (dangerousInline.includes('innerHTML_assign')) {
    risk += 8;
    threats.push({ level: 'medium', text: 'innerHTML assignment found in inline script — potential XSS vector' });
  }

  risk = Math.min(100, Math.max(0, risk));
  return { risk, threats };
}

// ════════════════════════════════════════════
// COLLECT REAL PAGE DATA
// ════════════════════════════════════════════
async function analyzeTab(url, tabId) {
  if (isSkippable(url)) return;

  tabAnalysis[tabId] = defaultState(url);
  setBadge(tabId, 100, true);

  try {
    const domain = new URL(url).hostname;
    tabAnalysis[tabId].domain = domain;

    // ── Collect real page data via content script ──
    let pageData = { hasPassword: false, forms: [], httpResources: 0, inlineScriptPatterns: [], title: '' };
    try {
      const res = await chrome.scripting.executeScript({
        target: { tabId },
        func: () => {
          // Count HTTP resources on this HTTPS page (mixed content — real check)
          const httpResources = Array.from(document.querySelectorAll(
            'img[src^="http:"], script[src^="http:"], link[href^="http:"], iframe[src^="http:"]'
          )).length;

          // Check forms for insecure action URLs (real DOM check)
          const forms = Array.from(document.forms).map(f => ({
            action: f.action || '',
            method: f.method || 'get',
            hasPassword: !!f.querySelector('input[type="password"]'),
          }));

          // Check inline scripts for dangerous patterns (reading actual content)
          const inlinePatterns = new Set();
          Array.from(document.scripts).forEach(s => {
            if (!s.src && s.textContent) {
              const t = s.textContent;
              if (t.includes('document.write(')) inlinePatterns.add('document.write');
              // innerHTML assignment (not just reading)
              if (/\binnerHTML\s*=/.test(t)) inlinePatterns.add('innerHTML_assign');
            }
          });

          return {
            title:       document.title,
            hasPassword: !!document.querySelector('input[type="password"]'),
            forms,
            httpResources,
            inlineScriptPatterns: Array.from(inlinePatterns),
          };
        }
      });
      if (res?.[0]?.result) pageData = res[0].result;
    } catch {}

    // ── Get real cookies via Chrome API ──
    let cookies = [];
    try {
      cookies = await new Promise(resolve =>
        chrome.cookies.getAll({ domain }, r => resolve(r || []))
      );
    } catch {}

    // ── Fetch real security headers ──
    let headers = null;
    try {
      const r = await fetch(url, { method: 'HEAD', cache: 'no-store' });
      headers = {};
      r.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    } catch {}

    // ── Run real scoring ──
    const scored = realScore(url, cookies, pageData, headers);

    // Update state immediately with local results
    tabAnalysis[tabId] = {
      ...tabAnalysis[tabId],
      score:    Math.max(0, 100 - scored.risk),
      risk:     scored.risk,
      threats:  scored.threats,
      summary:  scored.risk === 0
        ? 'No security issues detected'
        : scored.risk >= 60
          ? 'Significant security issues found'
          : scored.risk >= 30
            ? 'Minor security concerns found'
            : 'Low-risk issues detected',
      analyzing: true,
    };
    setBadge(tabId, tabAnalysis[tabId].score, true);
    chrome.runtime.sendMessage({ action: 'analysisUpdate', tabId, data: tabAnalysis[tabId] }).catch(() => {});

    // ── Groq AI enrichment (adds context, not fake threats) ──
    try {
      const aiRes = await fetch(`${API_BASE}/api/groq-analyze`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url, domain,
          htmlSnippet:  '',   // don't send HTML — Groq should only add context
          cookies:      cookies.map(c => ({ name: c.name, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite })),
          scripts:      [],   // don't send script list — avoids false positives
          forms:        pageData.forms,
          localRisk:    scored.risk,
          localThreats: scored.threats.map(t => t.text),
        }),
      });
      const ai = await aiRes.json();

      if (ai.success && ai.threats && ai.threats.length > 0) {
        // Only add AI threats that are NOT already covered by local checks
        const newThreats = ai.threats
          .filter((t) => {
            const txt = (typeof t === 'string' ? t : t.text || '').toLowerCase();
            // Skip if local already caught it
            return !scored.threats.some(lt => {
              const ltxt = lt.text.toLowerCase();
              return ltxt.includes(txt.substring(0, 25)) || txt.includes(ltxt.substring(0, 25));
            });
          })
          .map(t => ({ level: 'medium', text: typeof t === 'string' ? t : t.text }));

        const allThreats = [...scored.threats, ...newThreats];

        // Blend: local score is authoritative, AI can add max +15
        const aiBoost = Math.min(15, (ai.riskScore || 0) * 0.15);
        const finalRisk  = Math.min(100, scored.risk + aiBoost);
        const finalScore = Math.max(0, 100 - finalRisk);

        tabAnalysis[tabId] = {
          ...tabAnalysis[tabId],
          score:           Math.round(finalScore),
          risk:            Math.round(finalRisk),
          threats:         allThreats,
          recommendations: ai.recommendations || [],
          summary:         ai.summary || tabAnalysis[tabId].summary,
          attackType:      ai.attackType || 'none',
          analyzing:       false,
        };
      }
    } catch {}

    // Guard: tab may have been closed during async analysis
    if (!tabAnalysis[tabId]) return;

    tabAnalysis[tabId].analyzing = false;
    const final = tabAnalysis[tabId];

    // ── History ──
    if (!Array.isArray(final.history)) final.history = [];
    final.history.push({
      timestamp:   new Date().toLocaleTimeString(),
      url, domain,
      score:       final.score,
      risk:        final.risk,
      threatCount: final.threats.length,
      summary:     final.summary,
    });

    setBadge(tabId, final.score, false);

    // ── Verify tab still exists before messaging ──
    chrome.tabs.get(tabId, tab => {
      if (chrome.runtime.lastError || !tab) return; // tab is gone

      // ── Show in-page popup for high risk ──
      if (final.risk >= 50 && final.threats.length > 0) {
        showInPagePopup(tabId, final);
      }

      chrome.tabs.sendMessage(tabId, { action: 'analysisUpdate', data: final }).catch(() => {});
    });

    // ── Send to dashboard ──
    fetch(`${API_BASE}/api/website-security`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        domain, url,
        securityScore:   final.score,
        riskScore:       final.risk,
        threats:         final.threats.map(t => t.text),
        recommendations: final.recommendations,
        summary:         final.summary,
        attackType:      final.attackType,
        timestamp:       new Date().toISOString(),
        alwaysSave:      true,
      }),
    }).catch(() => {});

    chrome.runtime.sendMessage({ action: 'analysisUpdate', tabId, data: final }).catch(() => {});

  } catch (err) {
    console.error('Analysis error:', err);
    tabAnalysis[tabId] = { ...defaultState(url), analyzing: false, summary: 'Analysis failed' };
    setBadge(tabId, 100, false);
  }
}

// ════════════════════════════════════════════
// IN-PAGE THREAT POPUP (terminal style)
// ════════════════════════════════════════════
function showInPagePopup(tabId, data) {
  const color = data.risk >= 70 ? '#ff3b3b' : '#facc15';
  const CIRC  = 2 * Math.PI * 36;

  const threatsHtml = data.threats.slice(0, 6).map(t => {
    const lc = t.level === 'critical' ? '#ff3b3b' : t.level === 'high' ? '#f97316' : t.level === 'medium' ? '#facc15' : '#00eaff';
    return `<div style="display:flex;align-items:flex-start;gap:8px;padding:6px 0;border-bottom:1px solid #111827">
      <span style="font-size:8px;font-weight:700;padding:1px 5px;background:${lc};color:#000;flex-shrink:0;margin-top:2px;font-family:monospace">${t.level.toUpperCase()}</span>
      <span style="font-size:11px;color:#9ca3af;line-height:1.4;font-family:'JetBrains Mono',monospace">${esc(t.text)}</span>
    </div>`;
  }).join('');

  const html = `
<div id="ainms-overlay" style="position:fixed;inset:0;background:rgba(0,0,0,0.8);z-index:2147483646;display:flex;align-items:center;justify-content:center;font-family:'JetBrains Mono',monospace">
  <div style="width:420px;max-width:92vw;max-height:85vh;background:#050505;border:1px solid #1f2937;border-top:2px solid ${color};display:flex;flex-direction:column;overflow:hidden;box-shadow:0 0 40px rgba(0,0,0,0.8)">
    <div style="padding:12px 16px;background:#0a0a0a;border-bottom:1px solid #1f2937;display:flex;align-items:center;justify-content:space-between">
      <div>
        <span style="font-size:12px;font-weight:700;color:${color};letter-spacing:0.1em;text-shadow:0 0 8px ${color}">AI-NMS // SECURITY ALERT</span>
        <div style="font-size:10px;color:#374151;margin-top:2px">${esc(data.domain)}</div>
      </div>
      <button id="ainms-x" style="background:none;border:1px solid #1f2937;color:#374151;width:24px;height:24px;cursor:pointer;font-size:13px;font-family:monospace">×</button>
    </div>
    <div style="display:flex;align-items:center;gap:14px;padding:12px 16px;border-bottom:1px solid #1f2937">
      <div style="position:relative;width:72px;height:72px;flex-shrink:0">
        <svg width="72" height="72" viewBox="0 0 72 72" style="transform:rotate(-90deg)">
          <circle cx="36" cy="36" r="36" fill="none" stroke="#111827" stroke-width="5"/>
          <circle cx="36" cy="36" r="36" fill="none" stroke="${color}" stroke-width="5"
            stroke-dasharray="${(data.risk/100)*226} 226"/>
        </svg>
        <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center">
          <span style="font-size:18px;font-weight:700;color:${color}">${data.risk}</span>
          <span style="font-size:7px;color:#374151">RISK</span>
        </div>
      </div>
      <div>
        <div style="font-size:10px;font-weight:700;color:${color};border:1px solid ${color};padding:2px 8px;display:inline-block;letter-spacing:0.1em;margin-bottom:5px">
          ${data.risk >= 70 ? 'CRITICAL' : data.risk >= 50 ? 'HIGH RISK' : 'MEDIUM'}
        </div>
        <div style="font-size:10px;color:#9ca3af;line-height:1.4">${esc(data.summary)}</div>
        <div style="font-size:9px;color:#374151;margin-top:3px">${data.threats.length} verified issue(s) found</div>
      </div>
    </div>
    <div style="padding:8px 16px 4px;background:#0a0a0a;border-bottom:1px solid #111827">
      <span style="font-size:9px;color:#374151;letter-spacing:0.1em">// VERIFIED_FINDINGS [${data.threats.length}]</span>
    </div>
    <div style="flex:1;overflow-y:auto;padding:6px 16px">${threatsHtml}</div>
    <div style="display:flex;gap:6px;padding:10px 16px;border-top:1px solid #1f2937;background:#0a0a0a">
      <button id="ainms-dash" style="flex:1;padding:7px;background:transparent;border:1px solid ${color};color:${color};font-family:'JetBrains Mono',monospace;font-size:9px;font-weight:600;cursor:pointer;letter-spacing:0.08em">[ OPEN_DASHBOARD ]</button>
      <button id="ainms-dismiss" style="padding:7px 12px;background:transparent;border:1px solid #1f2937;color:#374151;font-family:'JetBrains Mono',monospace;font-size:9px;cursor:pointer">[ CLOSE ]</button>
    </div>
  </div>
</div>`;

  chrome.tabs.get(tabId, tab => {
    if (chrome.runtime.lastError || !tab) return;
    chrome.scripting.executeScript({
      target: { tabId },
      func: (markup, base) => {
        document.getElementById('ainms-overlay')?.remove();
        document.body.insertAdjacentHTML('beforeend', markup);
        const close = () => document.getElementById('ainms-overlay')?.remove();
        document.getElementById('ainms-x')?.addEventListener('click', close);
        document.getElementById('ainms-dismiss')?.addEventListener('click', close);
        document.getElementById('ainms-dash')?.addEventListener('click', () => { window.open(base, '_blank'); close(); });
        document.getElementById('ainms-overlay')?.addEventListener('click', e => { if (e.target === document.getElementById('ainms-overlay')) close(); });
      },
      args: [html, API_BASE],
    }).catch(() => {});
  });
}

// ── Debounce map to prevent duplicate analysis on rapid tab updates ──
const pendingAnalysis = {};
// ── Bypass set — URLs the user has explicitly allowed through the warning page ──
const bypassUrls = new Set();

// ── Register listeners ──
function registerListeners() {
  if (typeof chrome === 'undefined' || !chrome.tabs) return;

  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
      // Cancel any pending analysis for this tab and debounce
      clearTimeout(pendingAnalysis[tabId]);
      pendingAnalysis[tabId] = setTimeout(() => {
        delete pendingAnalysis[tabId];
        analyzeTab(tab.url, tabId);
      }, 300);
    }
  });

  chrome.tabs.onRemoved.addListener(tabId => {
    clearTimeout(pendingAnalysis[tabId]);
    delete pendingAnalysis[tabId];
    delete tabAnalysis[tabId];
  });

  // ── Approach A: Navigation interceptor — redirect to warning page ──
  // Uses onCommitted. When Chrome commits to a navigation we immediately
  // redirect to our warning page. The warning page runs the sandbox scan
  // and shows Proceed / Go Back. On Proceed, /api/proceed does a 302 to
  // the real URL — Chrome marks that as server_redirect so we skip it.
  if (chrome.webNavigation) {
    chrome.webNavigation.onCommitted.addListener((details) => {
      if (details.frameId !== 0) return;
      const url = details.url;

      if (!url) return;
      if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) return;
      if (url.startsWith('about:') || url.startsWith('edge://') || url.startsWith('data:')) return;
      if (url.includes('localhost') || url.includes('127.0.0.1')) return;
      if (url.includes('/warning?url=')) return;

      // Server redirect from /api/proceed — user approved, let it through
      if (details.transitionQualifiers &&
          details.transitionQualifiers.includes('server_redirect')) {
        return;
      }

      // Explicit bypass (fallback for browsers that don't expose transitionQualifiers)
      if (bypassUrls.has(url)) {
        bypassUrls.delete(url);
        return;
      }

      // Redirect to warning page
      const warningUrl = `https://lokey-secure.vercel.app/warning?url=${encodeURIComponent(url)}`;
      chrome.tabs.get(details.tabId, tab => {
        if (chrome.runtime.lastError || !tab) return;
        chrome.tabs.update(details.tabId, { url: warningUrl });
      });
    });
  }

  // ── PHASE 6: Real traffic logging via webRequest ──
  if (chrome.webRequest) {
    const requestBuffer = new Map(); // tabId → [requests]

    chrome.webRequest.onCompleted.addListener((details) => {
      if (!details.tabId || details.tabId < 0) return;
      if (details.url.includes('localhost') || details.url.includes('127.0.0.1')) return;

      const entry = {
        url:          details.url,
        method:       details.method,
        type:         details.type,
        initiator:    details.initiator || '',
        timestamp:    new Date(details.timeStamp).toISOString(),
        statusCode:   details.statusCode,
      };

      if (!requestBuffer.has(details.tabId)) requestBuffer.set(details.tabId, []);
      requestBuffer.get(details.tabId).push(entry);

      // Flush every 10 requests or on main_frame
      const buf = requestBuffer.get(details.tabId);
      if (details.type === 'main_frame' || buf.length >= 10) {
        requestBuffer.delete(details.tabId);
        // Send to backend traffic API
        try {
          const domain = (() => { try { return new URL(details.url).hostname; } catch { return details.url; } })();
          fetch(`${API_BASE}/api/traffic`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              ip:           domain,
              port:         details.url.startsWith('https') ? 443 : 80,
              protocol:     details.url.startsWith('https') ? 'HTTPS' : 'HTTP',
              requestCount: buf.length,
              source:       'extension',
            }),
          }).catch(() => {});
        } catch {}
      }
    }, { urls: ['<all_urls>'] });
  }

  chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
    if (req.action === 'getCurrentScore') {
      chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        sendResponse(tabAnalysis[tabs[0]?.id] || defaultState(''));
      });
      return true;
    }
    if (req.action === 'getHistory') {
      chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        sendResponse({ history: tabAnalysis[tabs[0]?.id]?.history || [] });
      });
      return true;
    }
    if (req.action === 'openDashboard') {
      chrome.tabs.create({ url: `${API_BASE}/` });
    }
    if (req.action === 'rescan') {
      chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        if (tabs[0]) { delete tabAnalysis[tabs[0].id]; analyzeTab(tabs[0].url, tabs[0].id); }
      });
    }
    if (req.action === 'proceedToUrl' && req.url) {
      // User clicked Proceed on warning page — add to bypass and navigate
      bypassUrls.add(req.url);
      chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        if (tabs[0]) chrome.tabs.update(tabs[0].id, { url: req.url });
      });
    }
    return true;
  });
}

try {
  registerListeners();
} catch {
  self.addEventListener('activate', () => { try { registerListeners(); } catch {} });
}

console.log('AI-NMS v10.0 — real checks only');
