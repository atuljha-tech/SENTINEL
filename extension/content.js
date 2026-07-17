// AI-NMS Content Script v10.0 — terminal widget + expandable panel

let widgetEl  = null;
let panelEl   = null;
let panelOpen = false;
let currentData = null;

function isExtensionValid() {
  try { return !!(chrome && chrome.runtime && chrome.runtime.id); } catch { return false; }
}
function isLocalhost() {
  const h = window.location.hostname;
  return h === 'localhost' || h === '127.0.0.1' || h === '0.0.0.0';
}

/* ── Colors ── */
function scoreColor(s) {
  if (s >= 80) return '#00ff88';
  if (s >= 60) return '#facc15';
  if (s >= 40) return '#f97316';
  return '#ff3b3b';
}
function levelColor(l) {
  if (l === 'critical') return '#ff3b3b';
  if (l === 'high')     return '#f97316';
  if (l === 'medium')   return '#facc15';
  return '#00eaff';
}
function riskLabel(r) {
  if (r >= 70) return 'CRITICAL';
  if (r >= 50) return 'HIGH';
  if (r >= 30) return 'MEDIUM';
  if (r >= 10) return 'LOW';
  return 'SAFE';
}
function esc(s) {
  if (!s) return '';
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

/* ══════════════════════════════════════
   FLOATING WIDGET — small terminal circle
   Click → expands panel
   ══════════════════════════════════════ */
function createWidget(score, threatCount) {
  document.getElementById('ainms-widget')?.remove();

  const color = scoreColor(score);
  const el = document.createElement('div');
  el.id = 'ainms-widget';

  el.style.cssText = `
    position:fixed!important;
    bottom:18px!important;left:18px!important;
    width:58px!important;height:58px!important;
    background:#050505!important;
    border:1.5px solid ${color}!important;
    box-shadow:0 0 12px ${color}40,0 4px 20px rgba(0,0,0,0.6)!important;
    z-index:2147483646!important;
    display:flex!important;flex-direction:column!important;
    align-items:center!important;justify-content:center!important;
    cursor:pointer!important;
    font-family:'JetBrains Mono','Fira Code',monospace!important;
    transition:transform 0.15s,box-shadow 0.15s!important;
    user-select:none!important;
  `;

  el.innerHTML = `
    <div style="font-size:16px;font-weight:700;color:${color};line-height:1;text-shadow:0 0 8px ${color}">${score}</div>
    <div style="font-size:7px;color:#374151;margin-top:2px;letter-spacing:0.08em">SEC</div>
    ${threatCount > 0
      ? `<div style="position:absolute;top:-5px;right:-5px;min-width:18px;height:18px;padding:0 4px;background:#ff3b3b;border:1px solid #050505;display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:700;color:#fff;font-family:monospace">${Math.min(threatCount,9)}</div>`
      : ''}
  `;

  el.onmouseenter = () => {
    el.style.transform = 'scale(1.08)';
    el.style.boxShadow = `0 0 20px ${color}60,0 6px 24px rgba(0,0,0,0.7)`;
  };
  el.onmouseleave = () => {
    el.style.transform = 'scale(1)';
    el.style.boxShadow = `0 0 12px ${color}40,0 4px 20px rgba(0,0,0,0.6)`;
  };
  el.onclick = e => { e.stopPropagation(); togglePanel(); };

  document.body.appendChild(el);
  widgetEl = el;
}

/* ══════════════════════════════════════
   EXPANDED PANEL — terminal style
   Shows full threat list on click
   ══════════════════════════════════════ */
function createPanel(data) {
  document.getElementById('ainms-panel')?.remove();

  const score   = data.score  ?? 100;
  const risk    = data.risk   ?? 0;
  const threats = data.threats ?? [];
  const color   = scoreColor(score);
  const domain  = data.domain || window.location.hostname;
  const summary = data.summary || (threats.length > 0 ? 'Threats detected' : 'Page appears secure');
  const CIRC    = 2 * Math.PI * 36;

  /* Build threats HTML */
  const threatsHtml = threats.length > 0
    ? threats.map((t, i) => {
        const lv  = t.level || 'low';
        const lc  = levelColor(lv);
        const tag = lv.toUpperCase();
        return `
          <div style="display:flex;align-items:flex-start;gap:8px;padding:6px 0;border-bottom:1px solid #111827">
            <span style="font-size:8px;font-weight:700;padding:1px 5px;background:${lc};color:#000;flex-shrink:0;margin-top:2px;font-family:monospace">${tag}</span>
            <span style="font-size:10.5px;color:#9ca3af;line-height:1.45;font-family:'JetBrains Mono',monospace">${esc(t.text || t)}</span>
          </div>`;
      }).join('')
    : `<div style="text-align:center;padding:20px;color:#00ff88;font-family:monospace;font-size:11px">
        <div style="font-size:20px;margin-bottom:6px">✓</div>
        // NO THREATS DETECTED
      </div>`;

  const el = document.createElement('div');
  el.id = 'ainms-panel';
  el.style.cssText = `
    position:fixed!important;
    bottom:86px!important;left:18px!important;
    width:340px!important;max-height:500px!important;
    background:#050505!important;
    border:1px solid #1f2937!important;
    border-top:1px solid ${color}!important;
    box-shadow:0 0 30px rgba(0,0,0,0.8),0 0 1px ${color}40!important;
    z-index:2147483645!important;
    font-family:'JetBrains Mono','Fira Code',monospace!important;
    display:flex!important;flex-direction:column!important;
    overflow:hidden!important;
    animation:ainmsUp 0.18s ease-out!important;
  `;

  el.innerHTML = `
    <style>
      @keyframes ainmsUp { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }
      #ainms-panel ::-webkit-scrollbar { width:2px }
      #ainms-panel ::-webkit-scrollbar-thumb { background:#1f2937 }
    </style>

    <!-- HEADER -->
    <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:#0a0a0a;border-bottom:1px solid #1f2937;flex-shrink:0">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="font-size:11px;font-weight:700;color:${color};letter-spacing:0.1em;text-shadow:0 0 8px ${color}">AI-NMS</span>
        <span style="font-size:9px;color:#374151;letter-spacing:0.06em">// SECURITY GUARDIAN</span>
      </div>
      <button id="ainms-x" style="background:none;border:1px solid #1f2937;color:#374151;width:22px;height:22px;cursor:pointer;font-size:12px;font-family:monospace;display:flex;align-items:center;justify-content:center">×</button>
    </div>

    <!-- SCORE ROW -->
    <div style="display:flex;align-items:center;gap:14px;padding:12px 14px;border-bottom:1px solid #1f2937;background:#0a0a0a;flex-shrink:0">
      <!-- Ring -->
      <div style="position:relative;width:76px;height:76px;flex-shrink:0">
        <svg width="76" height="76" viewBox="0 0 76 76" style="transform:rotate(-90deg)">
          <circle cx="38" cy="38" r="36" fill="none" stroke="#111827" stroke-width="5"/>
          <circle cx="38" cy="38" r="36" fill="none" stroke="${color}" stroke-width="5"
            stroke-dasharray="${(score/100)*CIRC} ${CIRC}" stroke-linecap="butt"
            style="filter:drop-shadow(0 0 4px ${color})"/>
        </svg>
        <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center">
          <span style="font-size:20px;font-weight:700;color:${color};text-shadow:0 0 10px ${color};line-height:1">${score}</span>
          <span style="font-size:7px;color:#374151;letter-spacing:0.08em;margin-top:1px">SCORE</span>
        </div>
      </div>
      <!-- Info -->
      <div style="flex:1;min-width:0">
        <div style="font-size:10px;font-weight:700;color:${color};border:1px solid ${color};background:${color}10;padding:2px 8px;display:inline-block;letter-spacing:0.1em;margin-bottom:5px">${riskLabel(risk)}</div>
        <div style="font-size:11px;color:#00eaff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;text-shadow:0 0 6px #00eaff40">${esc(domain)}</div>
        <div style="font-size:10px;color:#9ca3af;margin-top:3px;line-height:1.4">${esc(summary)}</div>
        <div style="font-size:9px;color:#374151;margin-top:3px">${threats.length} threat${threats.length !== 1 ? 's' : ''} detected</div>
      </div>
    </div>

    <!-- SITE OVERVIEW -->
    <div style="padding:8px 14px;background:#0a0a0a;border-bottom:1px solid #111827;flex-shrink:0">
      <div style="font-size:9px;color:#374151;letter-spacing:0.08em;margin-bottom:5px">// SITE_OVERVIEW</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:3px 12px">
        <div style="font-size:9px;color:#374151">PROTOCOL: <span style="color:${data.url && data.url.startsWith('https') ? '#00ff88' : '#ff3b3b'}">${data.url && data.url.startsWith('https') ? 'HTTPS ✓' : 'HTTP ✗'}</span></div>
        <div style="font-size:9px;color:#374151">RISK: <span style="color:${color}">${risk}/100</span></div>
        <div style="font-size:9px;color:#374151">ATTACK_TYPE: <span style="color:#facc15">${data.attackType && data.attackType !== 'none' ? data.attackType.toUpperCase() : 'NONE'}</span></div>
        <div style="font-size:9px;color:#374151">GOVERNED_BY: <span style="color:#00eaff">CIVIC AI</span></div>
      </div>
    </div>

    <!-- THREATS HEADER -->
    <div style="padding:8px 14px 6px;background:#0a0a0a;border-bottom:1px solid #111827;flex-shrink:0">
      <span style="font-size:9px;color:#374151;letter-spacing:0.1em;text-transform:uppercase">// VERIFIED_FINDINGS [${threats.length}]</span>
    </div>

    <!-- THREATS LIST -->
    <div style="flex:1;overflow-y:auto;padding:6px 14px">
      ${threatsHtml}
      ${threats.length === 0 ? '<div style="padding:12px 0;text-align:center"><div style="font-size:16px;margin-bottom:4px">✓</div><div style="font-size:9px;color:#00ff88;letter-spacing:0.06em">// NO SECURITY ISSUES DETECTED</div><div style="font-size:9px;color:#374151;margin-top:3px">Site follows security best practices</div></div>' : ''}
    </div>

    <!-- RECOMMENDATIONS -->
    ${data.recommendations && data.recommendations.length > 0 ? '<div style="padding:7px 14px;border-top:1px solid #111827;background:#0a0a0a;flex-shrink:0"><div style="font-size:9px;color:#374151;letter-spacing:0.08em;margin-bottom:4px">// AI_RECOMMENDATIONS</div>' + data.recommendations.slice(0,2).map(r => '<div style="font-size:9px;color:#9ca3af;padding:1px 0;display:flex;gap:5px"><span style="color:#00eaff;flex-shrink:0">AI&gt;</span><span>' + esc(r) + '</span></div>').join('') + '</div>' : ''}

    <!-- ACTIONS -->
    <div style="display:flex;gap:6px;padding:10px 14px;border-top:1px solid #1f2937;background:#0a0a0a;flex-shrink:0">
      <button id="ainms-dash" style="flex:1;padding:7px;background:transparent;border:1px solid ${color};color:${color};font-family:'JetBrains Mono',monospace;font-size:9px;font-weight:600;cursor:pointer;letter-spacing:0.08em;text-shadow:0 0 6px ${color}">[ OPEN_DASHBOARD ]</button>
      <button id="ainms-close" style="padding:7px 12px;background:transparent;border:1px solid #1f2937;color:#374151;font-family:'JetBrains Mono',monospace;font-size:9px;cursor:pointer;letter-spacing:0.06em">[ CLOSE ]</button>
    </div>
  `;

  document.body.appendChild(el);
  panelEl = el;

  document.getElementById('ainms-x')?.addEventListener('click', closePanel);
  document.getElementById('ainms-close')?.addEventListener('click', closePanel);
  document.getElementById('ainms-dash')?.addEventListener('click', () => {
    try {
      if (isExtensionValid()) chrome.runtime.sendMessage({ action: 'openDashboard' });
      else window.open('https://lokey-secure.vercel.app', '_blank');
    } catch { window.open('https://lokey-secure.vercel.app', '_blank'); }
    closePanel();
  });
}

function togglePanel() { panelOpen ? closePanel() : openPanel(); }

function openPanel() {
  if (!currentData) return;
  createPanel(currentData);
  panelOpen = true;
}

function closePanel() {
  panelEl?.remove();
  panelEl   = null;
  panelOpen = false;
}

/* ── Init ── */
function init() {
  if (!isExtensionValid()) { setTimeout(init, 2000); return; }
  try {
    chrome.runtime.sendMessage({ action: 'getCurrentScore' }, res => {
      if (chrome.runtime.lastError || !res) return;
      currentData = res;
      createWidget(res.score ?? 100, (res.threats ?? []).length);
    });
  } catch {}
}

function setupListener() {
  if (!isExtensionValid()) return;
  try {
    if (window._ainmsL) chrome.runtime.onMessage.removeListener(window._ainmsL);
    window._ainmsL = req => {
      if (req?.action === 'updateScore' || req?.action === 'analysisUpdate') {
        const d = req.data || req;
        currentData = d;
        // Update widget badge
        createWidget(d.score ?? 100, (d.threats ?? []).length);
        // If panel is open, refresh it with new data
        if (panelOpen) { closePanel(); openPanel(); }
      }
      // Handle sandbox scan result — show warning if risky
      if (req?.action === 'sandboxResult') {
        const d = req.data;
        if (d && d.riskScore >= 50) {
          // Post message to dashboard if open, otherwise show in-page overlay
          try {
            window.postMessage({ type: 'AINMS_SECURITY_WARNING', data: d }, '*');
          } catch {}
        }
      }
      return true;
    };
    chrome.runtime.onMessage.addListener(window._ainmsL);
  } catch {}
}

/* Close panel on outside click */
document.addEventListener('click', e => {
  if (panelOpen && panelEl && !panelEl.contains(e.target) && !widgetEl?.contains(e.target)) {
    closePanel();
  }
});

window.addEventListener('beforeunload', () => {
  widgetEl?.remove(); panelEl?.remove();
  if (window._ainmsL) { try { chrome.runtime.onMessage.removeListener(window._ainmsL); } catch {} }
});

if (!isLocalhost()) {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(() => { init(); setupListener(); }, 600));
  } else {
    setTimeout(() => { init(); setupListener(); }, 600);
  }
}
