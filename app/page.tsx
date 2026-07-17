'use client';

import { useState, useEffect, useRef } from 'react';
import SOCDashboard from '../components/SOCDashboard';
import WebsiteSecurityPanel from '../components/WebsiteSecurityPanel';
import ThreatPopup from '../components/ThreatPopup';
import SecurityWarningPopup, { SecurityWarningData } from '../components/SecurityWarningPopup';
import AttackSimulator from '../components/AttackSimulator';
import GovernanceFeed from '../components/GovernanceFeed';
import ThreatForecastPanel from '../components/ThreatForecastPanel';
import AgentActivityPanel from '../components/AgentActivityPanel';
import { playAlert, playScan, playBlock, preloadSounds } from '../lib/sounds';

/* ── Types ── */
interface TrafficData {
  _id: string; id?: string; ip: string; port: number; protocol: string;
  requestCount: number; timestamp: string; riskScore?: number;
  threatStatus?: string; attackType?: string; alertFlag?: boolean; aiReason?: string;
}
interface DetectionStats { _id: string; count: number; avgRiskScore: number; }
interface Alert {
  _id: string; threatStatus: string; attackType: string; riskScore: number;
  trafficData: { ip: string; port: number; protocol: string; requestCount: number };
  reasons?: string[];
}
interface BlockedIP { ip: string; blockedAt: string; reason: string; attackType: string; riskScore: number; }
interface ResponseLog {
  _id: string; ip: string; attackType: string; riskScore: number;
  decision: { action: string; reason: string; severity: string }; timestamp: string;
}
interface WebsiteScan { _id: string; domain: string; securityScore: number; riskScore: number; threats: string[]; timestamp: string; }
interface WebsiteAlert { _id: string; domain: string; riskScore: number; threats: string[]; severity: string; timestamp: string; }

type Tab = 'governance' | 'dashboard' | 'logs' | 'alerts' | 'response' | 'websecurity' | 'forecast' | 'agents';

// Demo URLs for landing page
const DEMO_URLS = [
  { url: 'https://github.com',                   label: 'github.com',             safe: true  },
  { url: 'https://example.com',                  label: 'example.com',            safe: true  },
  { url: 'http://login-verify-account.com',      label: 'login-verify-account',   safe: false },
  { url: 'https://uniswap-claim-airdrop.com',    label: 'uniswap-airdrop (fake)', safe: false },
];

const NAV: { id: Tab; label: string; hero?: boolean }[] = [
  { id: 'governance',  label: 'GOVERNANCE FEED',   hero: true },
  { id: 'dashboard',   label: 'DASHBOARD' },
  { id: 'logs',        label: 'TRAFFIC LOGS' },
  { id: 'alerts',      label: 'THREAT ANALYSIS' },
  { id: 'response',    label: 'RESPONSE ENGINE' },
  { id: 'websecurity', label: 'WEBSITE SECURITY' },
  { id: 'forecast',    label: 'THREAT FORECAST' },
  { id: 'agents',      label: 'AGENT API' },
];

function fmtTime(ts: string) {
  try { return new Date(ts).toLocaleTimeString('en-US', { hour12: false }); } catch { return '--:--:--'; }
}

function riskTag(score: number) {
  if (score >= 80) return <span className="t-tag red">CRITICAL</span>;
  if (score >= 60) return <span className="t-tag red">HIGH</span>;
  if (score >= 35) return <span className="t-tag yellow">MEDIUM</span>;
  return <span className="t-tag green">LOW</span>;
}

function statusTag(s: string) {
  if (s === 'Attack')     return <span className="t-tag red">ATTACK</span>;
  if (s === 'Suspicious') return <span className="t-tag yellow">SUSPICIOUS</span>;
  return <span className="t-tag green">NORMAL</span>;
}

function riskColor(s: number) {
  if (s >= 70) return 'var(--red)';
  if (s >= 35) return 'var(--yellow)';
  return 'var(--green)';
}

function barClass(pct: number) {
  if (pct >= 75) return 'danger';
  if (pct >= 50) return 'warn';
  return 'ok';
}

/* ── Landing Hero Component ── */
function LandingHero({ onEnterDashboard }: { onEnterDashboard: (url?: string) => void }) {
  const [inputUrl, setInputUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult]     = useState<any>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const analyze = async (urlToScan?: string) => {
    const target = (urlToScan ?? inputUrl).trim();
    if (!target) return;
    const full = target.startsWith('http') ? target : 'https://' + target;
    setScanning(true);
    setResult(null);
    try {
      const res = await fetch('/api/sandbox-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: full }),
      });
      const data = await res.json();
      if (data.success) setResult(data.result);
    } catch {}
    setScanning(false);
  };

  return (
    <div className="landing-hero">
      <div className="landing-grid" />
      <div className="landing-gradient" />

      {/* Nav bar */}
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 32px', borderBottom: '1px solid var(--border)', background: 'rgba(5,8,16,0.8)', backdropFilter: 'blur(8px)', zIndex: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--cyan)', display: 'inline-block', boxShadow: 'var(--cyan-glow)' }} />
          <span style={{ fontWeight: 700, color: 'var(--cyan)', fontSize: 14, letterSpacing: '0.1em', textShadow: 'var(--cyan-glow)' }}>SENTINEL</span>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="t-btn ghost" style={{ fontSize: 11 }} onClick={() => onEnterDashboard()}>
            SOC DASHBOARD →
          </button>
        </div>
      </div>

      {/* Hero content */}
      <div style={{ position: 'relative', zIndex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', maxWidth: 800, width: '100%', paddingTop: 60 }}>
        {/* Badge */}
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '4px 14px', background: 'rgba(0,212,255,0.08)', border: '1px solid rgba(0,212,255,0.2)', borderRadius: 20, marginBottom: 20, fontSize: 11, color: 'var(--cyan)' }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--green)', display: 'inline-block', animation: 'pulse-dot 1.5s infinite' }} />
          OKX.AI Genesis Hackathon 2026 · Agent Service Provider
        </div>

        <h1 className="landing-headline">
          The AI Security Layer<br /><span className="accent">Every Agent Needs</span>
        </h1>
        <p className="landing-subtitle">
          Multi-agent cyber defense. Real-time sandbox isolation. Civic governance audit trails.
          One API call to protect any OKX.AI agent from phishing, wallet drainers, and DDoS attacks.
        </p>

        {/* URL Input */}
        <div className="landing-input-wrap">
          <input
            ref={inputRef}
            className="landing-input"
            value={inputUrl}
            onChange={e => setInputUrl(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && !scanning) analyze(); }}
            placeholder="Enter any URL to see SENTINEL in action..."
          />
          <button
            className="landing-analyze-btn"
            onClick={() => analyze()}
            disabled={scanning || !inputUrl.trim()}
          >
            {scanning ? '⟳ SCANNING...' : 'ANALYZE →'}
          </button>
        </div>

        {/* Demo chips */}
        <div className="landing-demo-urls">
          <span style={{ fontSize: 10, color: 'var(--faint)', alignSelf: 'center' }}>TRY:</span>
          {DEMO_URLS.map(d => (
            <button
              key={d.url}
              className={`landing-demo-chip ${d.safe ? '' : 'danger'}`}
              onClick={() => { setInputUrl(d.url); analyze(d.url); }}
            >
              {d.label}
            </button>
          ))}
        </div>

        {/* Inline result preview */}
        {result && (
          <div className="t-slide-up glass-card" style={{ width: '100%', marginTop: 24, padding: 20 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <div style={{
                width: 64, height: 64, borderRadius: '50%', flexShrink: 0,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: result.riskScore >= 60 ? 'rgba(255,71,87,0.1)' : result.riskScore >= 35 ? 'rgba(255,211,42,0.1)' : 'rgba(0,255,136,0.1)',
                border: `2px solid ${result.riskScore >= 60 ? 'var(--red)' : result.riskScore >= 35 ? 'var(--yellow)' : 'var(--green)'}`,
              }}>
                <span style={{ fontSize: 20, fontWeight: 700, color: riskColor(result.riskScore) }}>{result.riskScore}</span>
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                  <span style={{ fontSize: 13, fontWeight: 700, color: result.sandboxVerdict === 'block' ? 'var(--red)' : result.sandboxVerdict === 'warning' ? 'var(--yellow)' : 'var(--green)' }}>
                    {result.sandboxVerdict === 'block' ? '⛔ BLOCKED' : result.sandboxVerdict === 'warning' ? '⚠ WARNING' : '✓ SAFE'}
                  </span>
                  {riskTag(result.riskScore)}
                </div>
                <div style={{ fontSize: 11, color: 'var(--muted)' }}>{result.domain} · {result.threats?.length ?? 0} threat{result.threats?.length !== 1 ? 's' : ''} · {result.scriptsCount} scripts</div>
                {result.threats?.[0] && (
                  <div style={{ fontSize: 10, color: 'var(--red)', marginTop: 4 }}>⚠ {result.threats[0].text ?? result.threats[0]}</div>
                )}
              </div>
              <button className="t-btn primary" style={{ fontSize: 11 }} onClick={() => onEnterDashboard()}>
                OPEN REPORT →
              </button>
            </div>
          </div>
        )}

        {/* Trust badges */}
        <div className="landing-trust">
          {[
            { label: 'Groq Llama-3.3-70B' },
            { label: 'Civic Governance' },
            { label: 'Playwright Sandbox' },
            { label: 'MCP Protocol' },
          ].map(t => (
            <div key={t.label} className="landing-trust-item">
              <span className="dot" />
              {t.label}
            </div>
          ))}
        </div>

        {/* Feature cards */}
        <div className="landing-features">
          {[
            { icon: '🛡️', title: 'SANDBOX ISOLATION', desc: 'Every URL is executed in an isolated Playwright browser before your agent touches it.' },
            { icon: '⚖️', title: 'CIVIC GOVERNANCE', desc: 'Every automated decision is logged to an immutable audit trail. Human review for borderline cases.' },
            { icon: '🤖', title: 'AGENT API', desc: '5 lines to protect any agent. POST /api/v1/agent/clearance — get clearanceGranted in <10s.' },
          ].map(f => (
            <div key={f.title} className="landing-feature">
              <div className="landing-feature-icon">{f.icon}</div>
              <div className="landing-feature-title">{f.title}</div>
              <div className="landing-feature-desc">{f.desc}</div>
            </div>
          ))}
        </div>

        {/* CTA */}
        <div style={{ display: 'flex', gap: 12, marginTop: 40 }}>
          <button className="t-btn primary" style={{ padding: '10px 28px', fontSize: 12 }} onClick={() => onEnterDashboard()}>
            OPEN SOC DASHBOARD →
          </button>
          <a href="/sandbox" target="_blank" className="t-btn" style={{ padding: '10px 28px', fontSize: 12, textDecoration: 'none' }}>
            SANDBOX SCANNER
          </a>
        </div>
      </div>
    </div>
  );
}

/* ── Main Dashboard Home ── */
export default function Home() {
  const [showLanding,   setShowLanding]   = useState(true);
  const [traffic,       setTraffic]       = useState<TrafficData[]>([]);
  const [stats,         setStats]         = useState<DetectionStats[]>([]);
  const [alerts,        setAlerts]        = useState<Alert[]>([]);
  const [blockedIPs,    setBlockedIPs]    = useState<BlockedIP[]>([]);
  const [responseLogs,  setResponseLogs]  = useState<ResponseLog[]>([]);
  const [websiteScans,  setWebsiteScans]  = useState<WebsiteScan[]>([]);
  const [websiteAlerts, setWebsiteAlerts] = useState<WebsiteAlert[]>([]);
  const [activeTab,     setActiveTab]     = useState<Tab>('governance');
  const [sidebarOpen,   setSidebarOpen]   = useState(false);
  const [detecting,     setDetecting]     = useState(false);
  const [autoResponse,  setAutoResponse]  = useState(true);
  const [lastScan,      setLastScan]      = useState('');
  const [currentTime,   setCurrentTime]   = useState('');
  const [showKnowledge, setShowKnowledge] = useState(false);
  const [currentThreat, setCurrentThreat] = useState<any>(null);
  const [showThreat,    setShowThreat]    = useState(false);
  const [aiLog,         setAiLog]         = useState<string[]>([]);
  const [civicLogs,     setCivicLogs]     = useState<any[]>([]);
  const [civicStats,    setCivicStats]    = useState<any>({});
  const [civicRevoked,  setCivicRevoked]  = useState(false);
  const [civicConnected, setCivicConnected] = useState<boolean | null>(null);
  const [recentSites,   setRecentSites]   = useState<any[]>([]);
  const [securityWarning, setSecurityWarning] = useState<SecurityWarningData | null>(null);
  const [ragKnowledge,  setRagKnowledge]  = useState<any>(null);
  const logRef = useRef<HTMLDivElement>(null);
  const prevAlertCount   = useRef(0);
  const prevBlockedCount = useRef(0);

  useEffect(() => {
    if (alerts.length > prevAlertCount.current) playAlert();
    prevAlertCount.current = alerts.length;
  }, [alerts.length]);

  useEffect(() => {
    if (blockedIPs.length > prevBlockedCount.current) playBlock();
    prevBlockedCount.current = blockedIPs.length;
  }, [blockedIPs.length]);

  useEffect(() => {
    const t = setInterval(() => setCurrentTime(new Date().toLocaleTimeString('en-US', { hour12: false })), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const unlock = () => { preloadSounds(); window.removeEventListener('click', unlock); };
    window.addEventListener('click', unlock, { once: true });
    return () => window.removeEventListener('click', unlock);
  }, []);

  useEffect(() => {
    const handler = (e: MessageEvent) => {
      if (e.data?.type === 'AINMS_SECURITY_WARNING' && e.data.data) {
        const d = e.data.data;
        setSecurityWarning({ url: d.url, domain: d.domain, riskScore: d.riskScore, securityScore: d.securityScore, threats: d.threats ?? [], sandboxVerdict: d.sandboxVerdict ?? 'warning', recommendations: d.recommendations ?? [] });
      }
    };
    window.addEventListener('message', handler);
    return () => window.removeEventListener('message', handler);
  }, []);

  const fetchTraffic  = async () => { try { const r = await fetch('/api/traffic');  const d = await r.json(); if (d.success) setTraffic(d.data ?? []); } catch {} };
  const fetchDetect   = async () => { try { const r = await fetch('/api/detect');   const d = await r.json(); if (d.success) { setStats(d.stats ?? []); setAlerts(d.alerts ?? []); } } catch {} };
  const fetchRespond  = async () => { try { const r = await fetch('/api/respond');  const d = await r.json(); if (d.success) { setBlockedIPs(d.blockedIPs ?? []); setResponseLogs(d.logs ?? []); } } catch {} };
  const fetchWebSec   = async () => { try { const r = await fetch('/api/website-security'); const d = await r.json(); if (d.success) { setWebsiteScans(d.scans ?? []); setWebsiteAlerts(d.alerts ?? []); } } catch {} };
  const fetchCivic    = async () => {
    try { const r = await fetch('/api/civic-audit'); const d = await r.json(); if (d.success) { setCivicLogs(d.logs ?? []); setCivicStats(d.stats ?? {}); setCivicRevoked(d.revoked ?? false); } } catch {}
  };
  const pingCivic = async () => {
    try { const r = await fetch('/api/civic-audit?action=ping'); const d = await r.json(); setCivicConnected(d.connected ?? false); } catch { setCivicConnected(false); }
  };
  const refreshAll = () => { fetchTraffic(); fetchDetect(); fetchRespond(); fetchWebSec(); fetchCivic(); };

  useEffect(() => {
    if (showLanding) return;
    refreshAll(); pingCivic();
    let es: EventSource | null = null;
    const connectSSE = () => {
      es = new EventSource('/api/live-updates');
      es.onmessage = (e) => {
        try {
          const d = JSON.parse(e.data);
          if (d.traffic) setTraffic(d.traffic.map((t: any) => ({ ...t, _id: t.id ?? t._id })));
          if (d.alerts) setAlerts(d.alerts.map((a: any) => ({
            _id: a.id ?? a._id,
            threatStatus: a.type === 'network' ? (a.severity === 'critical' ? 'Attack' : 'Suspicious') : 'Suspicious',
            attackType: a.attackType ?? 'Unknown', riskScore: a.riskScore,
            trafficData: { ip: a.ip ?? a.domain, port: 0, protocol: 'TCP', requestCount: 0 },
            reasons: a.threats,
          })));
          if (d.blockedIPs)   setBlockedIPs(d.blockedIPs);
          if (d.recentSites)  setRecentSites(d.recentSites);
          if (d.responseLogs) setResponseLogs(d.responseLogs.map((r: any) => ({ ...r, _id: r.id ?? r._id })));
        } catch {}
      };
      es.onerror = () => { es?.close(); setTimeout(connectSSE, 3000); };
    };
    connectSSE();
    const simulate = setInterval(() => { fetch('/api/simulate', { method: 'POST' }).catch(() => {}); }, 4000);
    return () => { es?.close(); clearInterval(simulate); };
  }, [showLanding]); // eslint-disable-line

  const pushAiLog = (line: string) => {
    setAiLog(prev => [...prev.slice(-49), line]);
    setTimeout(() => { logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: 'smooth' }); }, 50);
  };

  const runScan = async () => {
    setDetecting(true); playScan();
    pushAiLog('AI> initiating full network scan...');
    try {
      const r = await fetch('/api/analyze-all', { method: 'POST' });
      const d = await r.json();
      if (d.success) { setLastScan(new Date().toLocaleTimeString('en-US', { hour12: false })); pushAiLog(`AI> scan complete — ${d.analyzed} packets analyzed`); refreshAll(); }
    } catch { pushAiLog('AI> scan failed — check connection'); }
    finally { setDetecting(false); }
  };

  const fetchRAG = async (attackType: string) => {
    try {
      const r = await fetch(`/api/rag?attackType=${encodeURIComponent(attackType)}`);
      const d = await r.json();
      if (d.success) { setRagKnowledge(d.knowledge); setShowKnowledge(true); setTimeout(() => setShowKnowledge(false), 12000); }
    } catch {}
  };

  const execResponse = async (ip: string, attackType: string, riskScore: number, threatStatus: string) => {
    pushAiLog(`AI> executing response for ${ip} [${attackType}]`);
    try {
      const r = await fetch('/api/respond', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip, attackType, riskScore, threatStatus, autoExecute: autoResponse }) });
      const d = await r.json();
      if (d.success) { pushAiLog(`AI> action=${d.decision.action} severity=${d.decision.severity}`); refreshAll(); }
    } catch {}
  };

  const unblock = async (ip: string) => {
    try { const r = await fetch(`/api/respond?action=unblock&ip=${ip}`); const d = await r.json(); if (d.success) { pushAiLog(`AI> unblocked ${ip}`); fetchRespond(); } } catch {}
  };

  // Derived metrics
  const totalSafe    = traffic.filter(t => (t.riskScore ?? 0) < 35).length;
  const totalSuspect = traffic.filter(t => (t.riskScore ?? 0) >= 35 && (t.riskScore ?? 0) < 70).length;
  const totalAttack  = traffic.filter(t => (t.riskScore ?? 0) >= 70).length;
  const secScore     = traffic.length > 0 ? Math.round((totalSafe / traffic.length) * 100) : 100;
  const avgRequests  = traffic.length > 0 ? traffic.reduce((s, t) => s + (t.requestCount ?? 1), 0) / traffic.length : 0;
  const cpuPct       = Math.min(100, Math.round(15 + (totalAttack / Math.max(traffic.length, 1)) * 60 + Math.min(avgRequests / 5, 20)));
  const ramPct       = Math.min(100, Math.round(20 + (traffic.length / 5) + alerts.length * 1.5));
  const netPct       = Math.min(100, Math.round((alerts.length / Math.max(traffic.length, 1)) * 100 * 3));
  const storagePct   = Math.min(100, Math.round(((traffic.length + alerts.length + blockedIPs.length) / 600) * 100));

  if (showLanding) {
    return (
      <>
        {securityWarning && (
          <SecurityWarningPopup data={securityWarning} onLeave={() => setSecurityWarning(null)} onProceed={() => setSecurityWarning(null)} onViewReport={() => { setShowLanding(false); setActiveTab('websecurity'); setSecurityWarning(null); }} />
        )}
        <LandingHero onEnterDashboard={() => setShowLanding(false)} />
      </>
    );
  }

  return (
    <div className="t-shell">
      {securityWarning && (
        <SecurityWarningPopup data={securityWarning} onLeave={() => setSecurityWarning(null)} onProceed={() => setSecurityWarning(null)} onViewReport={() => { setActiveTab('websecurity'); setSecurityWarning(null); }} />
      )}

      {/* ── SIDEBAR ── */}
      <aside className={`t-sidebar${sidebarOpen ? ' open' : ''}`}>
        <div className="t-sidebar-logo">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--cyan)', display: 'inline-block', boxShadow: 'var(--cyan-glow)' }} />
            <div className="t-sidebar-logo-title">SENTINEL</div>
          </div>
          <div className="t-sidebar-logo-sub">AI SECURITY LAYER v2.0 · OKX.AI ASP</div>
        </div>

        <div style={{ padding: '8px 0', flex: 1, overflowY: 'auto' }}>
          <div className="t-nav-section">// NAVIGATION</div>
          {NAV.map(item => (
            <div key={item.id} className={`t-nav-item${activeTab === item.id ? ' active' : ''}`}
              onClick={() => { setActiveTab(item.id); setSidebarOpen(false); }}>
              <span className="t-nav-prefix">›</span>
              <span style={{ flex: 1 }}>{item.label}</span>
              {item.hero && <span style={{ fontSize: 8, color: 'var(--cyan)', opacity: 0.7 }}>★</span>}
              {item.id === 'alerts'      && alerts.length > 0      && <span className="t-badge">{alerts.length > 99 ? '99+' : alerts.length}</span>}
              {item.id === 'response'    && blockedIPs.length > 0  && <span className="t-badge" style={{ background: 'var(--yellow)', color: '#000' }}>{blockedIPs.length}</span>}
              {item.id === 'websecurity' && websiteAlerts.length > 0 && <span className="t-badge" style={{ background: 'var(--cyan)', color: '#000' }}>{websiteAlerts.length}</span>}
            </div>
          ))}

          <div className="t-nav-section" style={{ marginTop: 8 }}>// TOOLS</div>
          <div className="t-nav-item" onClick={runScan} style={{ opacity: detecting ? 0.5 : 1 }}>
            <span className="t-nav-prefix">$</span>
            <span>{detecting ? 'SCANNING...' : 'RUN AI SCAN'}</span>
          </div>
          <div className="t-nav-item" onClick={refreshAll}>
            <span className="t-nav-prefix">$</span><span>REFRESH DATA</span>
          </div>
          <div className="t-nav-item" onClick={() => setAutoResponse(p => !p)}>
            <span className="t-nav-prefix">$</span>
            <span>AUTO-RESPONSE: <span style={{ color: autoResponse ? 'var(--green)' : 'var(--red)' }}>{autoResponse ? 'ON' : 'OFF'}</span></span>
          </div>
          <div className="t-nav-item">
            <span className="t-nav-prefix">$</span>
            <a href="/sandbox" target="_blank" style={{ color: 'var(--cyan)', textDecoration: 'none' }}>SANDBOX ↗</a>
          </div>
          <div className="t-nav-item" onClick={() => setShowLanding(true)}>
            <span className="t-nav-prefix">$</span><span>← LANDING PAGE</span>
          </div>
          <div className="t-nav-item">
            <span className="t-nav-prefix">$</span>
            <a href="/api/export?format=json" download style={{ color: 'inherit', textDecoration: 'none' }}>EXPORT JSON</a>
          </div>
        </div>

        <div className="t-sidebar-footer">
          <div className="t-sidebar-footer-row">
            <span className="t-pulse" style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--green)', display: 'inline-block' }} />
            <span>SENTINEL ACTIVE</span>
          </div>
          <div style={{ color: 'var(--faint)', fontSize: 9, marginTop: 2 }}>OKX.AI AGENT SERVICE PROVIDER</div>
          {lastScan && <div style={{ color: 'var(--faint)', fontSize: 9, marginTop: 2 }}>LAST SCAN: {lastScan}</div>}
        </div>
      </aside>

      {sidebarOpen && <div onClick={() => setSidebarOpen(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', zIndex: 39 }} />}

      {/* ── MAIN ── */}
      <div className="t-main">
        {/* STATUS BAR */}
        <div className="t-statusbar">
          <button className="mobile-only t-btn" style={{ border: 'none', padding: '0 12px 0 0', marginRight: 8 }} onClick={() => setSidebarOpen(!sidebarOpen)}>☰</button>
          <div className="t-statusbar-item"><span className="ok">●</span> SYS:OK</div>
          <div className="t-statusbar-item"><span className={alerts.length > 0 ? 'warn' : 'ok'}>●</span> NET:{alerts.length > 0 ? 'ALERT' : 'ACTIVE'}</div>
          <div className="t-statusbar-item"><span className="ok">●</span> AI:ONLINE</div>
          <div className="t-statusbar-item" style={{ color: 'var(--faint)' }}>TRAFFIC:{traffic.length}</div>
          <div className="t-statusbar-item" style={{ color: 'var(--faint)' }}>BLOCKED:{blockedIPs.length}</div>
          <div className="t-statusbar-right">
            {alerts.length > 0 && <div className="t-statusbar-item"><span className="err">⚠ {alerts.length} ALERTS</span></div>}
            <div className="t-statusbar-item" style={{ color: civicRevoked ? 'var(--red)' : 'var(--green)' }}>
              CIVIC:{civicRevoked ? 'REVOKED' : civicConnected === true ? 'CONNECTED' : civicConnected === false ? 'LOCAL' : '...'}
            </div>
            <div className="t-statusbar-item" style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan)' }}>{currentTime}</div>
          </div>
        </div>

        {/* CONTENT */}
        <div className="t-content t-fade-in">
          {/* METRICS ROW */}
          <div className="t-metrics-grid">
            {[
              { label: 'TOTAL_REQUESTS', value: traffic.length,     cls: 'default' },
              { label: 'ACTIVE_ALERTS',  value: alerts.length,      cls: alerts.length > 0 ? 'danger' : 'ok' },
              { label: 'BLOCKED_IPS',    value: blockedIPs.length,  cls: blockedIPs.length > 0 ? 'warn' : 'ok' },
              { label: 'SAFE_TRAFFIC',   value: totalSafe,           cls: 'ok' },
              { label: 'SITES_SCANNED',  value: websiteScans.length, cls: 'default' },
            ].map((m, i) => (
              <div key={i} className="t-metric">
                <div className="t-metric-label">{m.label}</div>
                <div className={`t-metric-value ${m.cls}`}>{m.value}</div>
                <div className="t-metric-sub">// LIVE</div>
              </div>
            ))}
          </div>

          {/* GOVERNANCE TAB — The Hero Tab */}
          {activeTab === 'governance' && (
            <GovernanceFeed
              logs={civicLogs}
              stats={civicStats}
              revoked={civicRevoked}
              connected={civicConnected}
              onRevoke={async () => {
                const action = civicRevoked ? 'restore' : 'revoke';
                try {
                  const r = await fetch('/api/civic-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action }) });
                  const d = await r.json();
                  setCivicRevoked(d.revoked ?? !civicRevoked);
                  await fetchCivic();
                } catch {}
              }}
              onRefresh={fetchCivic}
            />
          )}

          {/* DASHBOARD TAB */}
          {activeTab === 'dashboard' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              <div className="t-grid-2" style={{ marginBottom: 1 }}>
                <div className="t-panel">
                  <div className="t-panel-header"><span className="t-panel-title">RESOURCE_MONITOR</span><span className="t-panel-meta">LIVE</span></div>
                  <div className="t-panel-body">
                    {[
                      { label: 'CPU',     pct: cpuPct,     sub: `${totalAttack} attacks` },
                      { label: 'RAM',     pct: ramPct,     sub: `${traffic.length} logs` },
                      { label: 'NETWORK', pct: netPct,     sub: `${alerts.length} alerts` },
                      { label: 'STORAGE', pct: storagePct, sub: `${traffic.length + alerts.length} entries` },
                    ].map(b => (
                      <div key={b.label} className="t-bar-row" style={{ marginBottom: 10 }}>
                        <span className="t-bar-label">{b.label}</span>
                        <div style={{ flex: 1 }}>
                          <div className="t-bar-track"><div className={`t-bar-fill ${barClass(b.pct)}`} style={{ width: `${b.pct}%` }} /></div>
                          <div style={{ fontSize: 9, color: 'var(--faint)', marginTop: 2 }}>{b.sub}</div>
                        </div>
                        <span className="t-bar-pct" style={{ color: b.pct >= 75 ? 'var(--red)' : b.pct >= 50 ? 'var(--yellow)' : 'var(--green)' }}>{b.pct}%</span>
                      </div>
                    ))}
                    <hr className="t-divider" />
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8, marginTop: 8 }}>
                      {[
                        { l: 'SAFE',    v: totalSafe,    c: 'var(--green)' },
                        { l: 'SUSPECT', v: totalSuspect, c: 'var(--yellow)' },
                        { l: 'ATTACK',  v: totalAttack,  c: 'var(--red)' },
                      ].map(r => (
                        <div key={r.l}>
                          <div className="t-label">{r.l}</div>
                          <div style={{ fontSize: 20, fontWeight: 700, color: r.c, textShadow: `0 0 8px ${r.c}` }}>{r.v}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
                <div className="t-panel">
                  <div className="t-panel-header"><span className="t-panel-title">SECURITY_SCORE</span><span className="t-panel-meta">COMPUTED</span></div>
                  <div className="t-panel-body" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
                    <div style={{ fontSize: 72, fontWeight: 700, color: secScore >= 70 ? 'var(--green)' : secScore >= 40 ? 'var(--yellow)' : 'var(--red)', textShadow: `0 0 30px ${secScore >= 70 ? 'var(--green)' : secScore >= 40 ? 'var(--yellow)' : 'var(--red)'}`, lineHeight: 1, letterSpacing: '-0.04em' }}>
                      {secScore}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--faint)', marginTop: 6, letterSpacing: '0.12em' }}>SECURITY INDEX / 100</div>
                    <div style={{ marginTop: 16, width: '100%' }}>
                      <div className="t-bar-track" style={{ height: 8 }}><div className={`t-bar-fill ${barClass(100 - secScore)}`} style={{ width: `${secScore}%` }} /></div>
                    </div>
                    <div style={{ marginTop: 14, fontSize: 11, color: 'var(--muted)', textAlign: 'center' }}>
                      {secScore >= 80 ? '// SYSTEM SECURE' : secScore >= 50 ? '// THREATS DETECTED' : '// CRITICAL STATE'}
                    </div>
                    <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
                      {stats.map(s => (
                        <div key={s._id} style={{ textAlign: 'center' }}>
                          <div style={{ fontSize: 9, color: 'var(--faint)' }}>{s._id?.toUpperCase()}</div>
                          <div style={{ fontSize: 14, fontWeight: 700, color: s._id === 'Attack' ? 'var(--red)' : s._id === 'Suspicious' ? 'var(--yellow)' : 'var(--green)' }}>{s.count}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
              <SOCDashboard traffic={traffic} stats={stats} alerts={alerts} blockedIPs={blockedIPs} />
              <AttackSimulator />
            </div>
          )}

          {/* TRAFFIC LOGS TAB */}
          {activeTab === 'logs' && (
            <div className="t-panel">
              <div className="t-panel-header">
                <span className="t-panel-title">LIVE_TRAFFIC_FEED</span>
                <span className="t-panel-meta">{traffic.length} PACKETS</span>
              </div>
              <div className="t-panel-body" style={{ padding: 0 }}>
                <table className="t-table">
                  <thead><tr><th>TIME</th><th>IP</th><th>PORT</th><th>PROTOCOL</th><th>REQUESTS</th><th>RISK</th><th>STATUS</th><th>ATTACK TYPE</th><th>AI REASON</th></tr></thead>
                  <tbody>
                    {traffic.slice(0, 100).map((t, i) => (
                      <tr key={t._id ?? i}>
                        <td className="t-td-time">{fmtTime(t.timestamp)}</td>
                        <td className="t-td-ip">{t.ip}</td>
                        <td>{t.port}</td>
                        <td style={{ color: 'var(--faint)' }}>{t.protocol}</td>
                        <td>{t.requestCount}</td>
                        <td className="t-td-score" style={{ color: riskColor(t.riskScore ?? 0) }}>{t.riskScore ?? '-'}</td>
                        <td>{statusTag(t.threatStatus ?? 'Normal')}</td>
                        <td><span style={{ color: t.attackType && t.attackType !== 'None' ? 'var(--yellow)' : 'var(--faint)' }}>{t.attackType ?? '-'}</span></td>
                        <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--faint)', fontSize: 10 }}>{t.aiReason ?? ''}</td>
                      </tr>
                    ))}
                    {traffic.length === 0 && <tr><td colSpan={9} style={{ textAlign: 'center', color: 'var(--faint)', padding: 24 }}>// awaiting traffic data...</td></tr>}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* THREAT ANALYSIS TAB */}
          {activeTab === 'alerts' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              <div className="t-panel">
                <div className="t-panel-header">
                  <span className="t-panel-title">ACTIVE_THREATS</span>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <span className="t-panel-meta">{alerts.length} ALERTS</span>
                    <button className="t-btn primary" style={{ fontSize: 9, padding: '2px 10px' }} onClick={runScan} disabled={detecting}>
                      {detecting ? 'SCANNING...' : 'RUN AI SCAN'}
                    </button>
                  </div>
                </div>
                <div className="t-panel-body" style={{ padding: 0 }}>
                  {alerts.length === 0
                    ? <div style={{ padding: 24, textAlign: 'center', color: 'var(--faint)', fontSize: 11 }}>// No active threats detected</div>
                    : alerts.slice(0, 50).map((a, i) => (
                      <div key={a._id ?? i} className="t-alert-line" style={{ padding: '8px 14px' }}>
                        <div className={`t-alert-tag ${a.riskScore >= 80 ? 'danger' : a.riskScore >= 60 ? 'danger' : 'warn'}`}>
                          {a.riskScore >= 80 ? 'CRIT' : a.riskScore >= 60 ? 'HIGH' : 'MED'}
                        </div>
                        <span className="t-alert-ip">{a.trafficData?.ip}</span>
                        <span className="t-alert-type"
                          style={{ cursor: 'pointer' }}
                          onClick={() => { setCurrentThreat(a); setShowThreat(true); fetchRAG(a.attackType); }}>
                          {a.attackType}
                        </span>
                        <span className="t-alert-score" style={{ color: riskColor(a.riskScore) }}>{a.riskScore}</span>
                        <span className="t-alert-reason">{a.reasons?.[0] ?? a.threatStatus}</span>
                        <button className="t-alert-btn" onClick={() => execResponse(a.trafficData?.ip, a.attackType, a.riskScore, a.threatStatus)}>
                          RESPOND
                        </button>
                      </div>
                    ))
                  }
                </div>
              </div>
              {showThreat && currentThreat && (
                <ThreatPopup
                  domain={currentThreat.trafficData?.ip ?? 'unknown'}
                  riskScore={currentThreat.riskScore ?? 0}
                  threats={currentThreat.reasons ?? []}
                  onClose={() => setShowThreat(false)}
                />
              )}
            </div>
          )}

          {/* RESPONSE ENGINE TAB */}
          {activeTab === 'response' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              <div className="t-grid-2">
                <div className="t-panel">
                  <div className="t-panel-header"><span className="t-panel-title">BLOCKED_IPS</span><span className="t-panel-meta">{blockedIPs.length} ENTRIES</span></div>
                  <div className="t-panel-body" style={{ padding: 0 }}>
                    <table className="t-table">
                      <thead><tr><th>IP</th><th>ATTACK TYPE</th><th>RISK</th><th>BLOCKED AT</th><th>ACTION</th></tr></thead>
                      <tbody>
                        {blockedIPs.map((b, i) => (
                          <tr key={b.ip ?? i}>
                            <td className="t-td-ip">{b.ip}</td>
                            <td style={{ color: 'var(--yellow)' }}>{b.attackType}</td>
                            <td className="t-td-score" style={{ color: riskColor(b.riskScore) }}>{b.riskScore}</td>
                            <td className="t-td-time">{fmtTime(b.blockedAt)}</td>
                            <td><button className="t-alert-btn cyan" onClick={() => unblock(b.ip)}>UNBLOCK</button></td>
                          </tr>
                        ))}
                        {blockedIPs.length === 0 && <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--faint)', padding: 20 }}>// No blocked IPs</td></tr>}
                      </tbody>
                    </table>
                  </div>
                </div>
                <div className="t-panel">
                  <div className="t-panel-header"><span className="t-panel-title">RESPONSE_LOG</span><span className="t-panel-meta">{responseLogs.length} ENTRIES</span></div>
                  <div className="t-panel-body" style={{ padding: 0 }}>
                    <table className="t-table">
                      <thead><tr><th>IP</th><th>ACTION</th><th>SEVERITY</th><th>TIME</th></tr></thead>
                      <tbody>
                        {responseLogs.slice(0, 30).map((r, i) => (
                          <tr key={r._id ?? i}>
                            <td className="t-td-ip">{r.ip}</td>
                            <td style={{ color: r.decision?.action === 'BLOCK_IP' ? 'var(--red)' : r.decision?.action === 'RATE_LIMIT' ? 'var(--yellow)' : 'var(--green)' }}>{r.decision?.action}</td>
                            <td>{riskTag(r.riskScore)}</td>
                            <td className="t-td-time">{fmtTime(r.timestamp)}</td>
                          </tr>
                        ))}
                        {responseLogs.length === 0 && <tr><td colSpan={4} style={{ textAlign: 'center', color: 'var(--faint)', padding: 20 }}>// No response actions yet</td></tr>}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
              {/* AI Log */}
              <div className="t-panel">
                <div className="t-panel-header"><span className="t-panel-title">ORCHESTRATOR_LOG</span><span className="t-panel-meta">AI AGENT</span></div>
                <div className="t-panel-body" style={{ padding: '8px 14px' }}>
                  <div ref={logRef} className="t-log-stream">
                    {aiLog.length === 0
                      ? <div style={{ color: 'var(--faint)' }}>// SENTINEL orchestrator ready — run AI scan or block an IP</div>
                      : aiLog.map((l, i) => (
                        <div key={i} className="t-ai-line" style={{ color: l.includes('error') ? 'var(--red)' : l.includes('action=BLOCK') ? 'var(--red)' : l.includes('complete') ? 'var(--green)' : 'var(--muted)' }}>
                          {l}
                        </div>
                      ))
                    }
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'websecurity' && (
            <WebsiteSecurityPanel />
          )}

          {activeTab === 'forecast' && <ThreatForecastPanel />}

          {activeTab === 'agents' && <AgentActivityPanel />}
        </div>
      </div>
    </div>
  );
}
