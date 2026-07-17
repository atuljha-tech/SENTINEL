// AI-NMS Popup v10.0 — terminal style

const CIRC = 2 * Math.PI * 46; // r=46

function scoreColor(s) {
  if (s >= 80) return '#00ff88';
  if (s >= 60) return '#facc15';
  if (s >= 40) return '#f97316';
  return '#ff3b3b';
}

function riskLabel(r) {
  if (r >= 70) return 'CRITICAL';
  if (r >= 50) return 'HIGH';
  if (r >= 30) return 'MEDIUM';
  if (r >= 10) return 'LOW';
  return 'SAFE';
}

function levelClass(l) {
  if (l === 'critical') return 'critical';
  if (l === 'high')     return 'high';
  if (l === 'medium')   return 'medium';
  return 'low';
}

function esc(s) {
  if (!s) return '';
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

/* ── Apply score to ring + badge ── */
function applyScore(score, risk) {
  const color  = scoreColor(score);
  const offset = CIRC - (score / 100) * CIRC;

  const num  = document.getElementById('scoreNum');
  const fill = document.getElementById('ringFill');
  const tag  = document.getElementById('riskTag');
  const mRisk = document.getElementById('mRisk');

  num.textContent = score;
  num.style.color = color;
  num.style.textShadow = `0 0 10px ${color}`;

  fill.style.stroke = color;
  fill.style.strokeDashoffset = offset;

  const label = riskLabel(risk);
  tag.textContent = label;
  tag.style.color = color;
  tag.style.borderColor = color;
  tag.style.background = `${color}12`;

  mRisk.textContent = risk;
  mRisk.style.color = color;
}

/* ── Render threats ── */
function renderThreats(threats) {
  const el = document.getElementById('threatsList');
  const mT = document.getElementById('mThreats');
  const tc = document.getElementById('threatCount');

  mT.textContent = threats.length;
  tc.textContent = `${threats.length} threat${threats.length !== 1 ? 's' : ''} detected`;

  if (!threats || threats.length === 0) {
    el.innerHTML = `<div class="no-threats"><div class="no-threats-icon">✓</div>// NO THREATS DETECTED<br><span style="font-size:9px;color:#374151">system appears secure</span></div>`;
    return;
  }

  el.innerHTML = threats.map(t => {
    const lv  = t.level || 'low';
    const cls = levelClass(lv);
    return `<div class="t-item ${cls}">
      <span class="t-tag ${cls}">${lv.toUpperCase()}</span>
      <span class="t-text">${esc(t.text || t)}</span>
    </div>`;
  }).join('');
}

/* ── Render history ── */
function renderHistory(history) {
  const el = document.getElementById('historyList');
  const mS = document.getElementById('mSites');
  mS.textContent = history.length;

  if (!history || history.length === 0) {
    el.innerHTML = `<div class="no-history">// no sites scanned this session</div>`;
    return;
  }

  el.innerHTML = [...history].reverse().map(h => {
    const c = scoreColor(h.score);
    return `<div class="h-item">
      <div class="h-score" style="color:${c};border-color:${c};background:${c}10">${h.score}</div>
      <div class="h-info">
        <div class="h-domain">${esc(h.domain || h.url)}</div>
        <div class="h-meta">${h.threatCount} threat${h.threatCount !== 1 ? 's' : ''} // risk:${h.risk}</div>
      </div>
      <div class="h-time">${h.timestamp}</div>
    </div>`;
  }).join('');
}

/* ── Render tips ── */
function renderTips(recommendations) {
  const el = document.getElementById('tipsList');
  const defaults = [
    'Always verify HTTPS before entering credentials',
    'Clear cookies regularly to reduce tracking',
    'Hover links to verify destination before clicking',
    'Use a password manager + enable 2FA everywhere',
    'Suspicious emails asking to "verify" = phishing',
  ];
  const tips = (recommendations && recommendations.length > 0) ? recommendations : defaults;
  el.innerHTML = tips.map(t => `
    <div class="tip-item">
      <span class="tip-prefix">AI&gt;</span>
      <span class="tip-text">${esc(t)}</span>
    </div>`).join('');
}

/* ── Show/hide states ── */
function showScanning(domain) {
  document.getElementById('scanState').classList.remove('hidden');
  document.getElementById('mainContent').style.display = 'none';
  document.getElementById('scanDomain').textContent = domain ? `// ${domain}` : '';
}

function showMain() {
  document.getElementById('scanState').classList.add('hidden');
  document.getElementById('mainContent').style.display = 'block';
}

/* ── Full update ── */
function updateUI(data, history) {
  if (data.analyzing) { showScanning(data.domain); return; }
  showMain();

  const score = data.score ?? 100;
  const risk  = data.risk  ?? 0;

  applyScore(score, risk);

  let domain = data.domain || '';
  if (!domain && data.url) {
    try { domain = new URL(data.url).hostname; } catch {}
  }
  document.getElementById('domainVal').textContent  = domain || '// unknown';
  document.getElementById('summaryVal').textContent = data.summary || '// analysis complete';

  renderThreats(data.threats || []);
  renderHistory(history || data.history || []);
  renderTips(data.recommendations || []);
}

/* ── Tabs ── */
document.querySelectorAll('.tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
  });
});

/* ── Buttons ── */
document.getElementById('btnDashboard').addEventListener('click', () => {
  chrome.tabs.create({ url: 'https://lokey-secure.vercel.app/' });
});

document.getElementById('btnRescan').addEventListener('click', () => {
  showScanning('');
  chrome.runtime.sendMessage({ action: 'rescan' });
  setTimeout(loadData, 3000);
});

/* ── Clock ── */
function tick() { document.getElementById('clock').textContent = new Date().toLocaleTimeString('en-US', { hour12: false }); }
tick();
setInterval(tick, 1000);

/* ── Load ── */
function loadData() {
  chrome.runtime.sendMessage({ action: 'getCurrentScore' }, data => {
    chrome.runtime.sendMessage({ action: 'getHistory' }, histRes => {
      updateUI(data || {}, histRes?.history || []);
    });
  });
}

chrome.runtime.onMessage.addListener(msg => {
  if (msg.action === 'analysisUpdate') {
    chrome.runtime.sendMessage({ action: 'getHistory' }, histRes => {
      updateUI(msg.data, histRes?.history || []);
    });
  }
});

loadData();
