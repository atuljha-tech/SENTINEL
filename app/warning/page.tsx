'use client';

import { useEffect, useState, useRef } from 'react';

interface Threat { level: string; text: string; }

interface ScanResult {
  url: string;
  domain: string;
  riskScore: number;
  securityScore: number;
  threats: Threat[];
  sandboxVerdict: 'safe' | 'warning' | 'block';
  recommendations: string[];
  scriptsCount: number;
  cookiesCount: number;
  mixedContent: number;
  suspiciousPatterns: string[];
}

function levelColor(l: string) {
  if (l === 'critical') return '#ff3b3b';
  if (l === 'high')     return '#f97316';
  if (l === 'medium')   return '#facc15';
  return '#00eaff';
}
function scoreColor(s: number) {
  if (s >= 80) return '#00ff88';
  if (s >= 60) return '#facc15';
  if (s >= 40) return '#f97316';
  return '#ff3b3b';
}
function verdictColor(v: string) {
  if (v === 'block')   return '#ff3b3b';
  if (v === 'warning') return '#facc15';
  return '#00ff88';
}
function riskLabel(r: number) {
  if (r >= 80) return 'CRITICAL';
  if (r >= 60) return 'HIGH RISK';
  if (r >= 35) return 'WARNING';
  return 'SAFE';
}

const SCAN_STEPS = [
  'Intercepting navigation request...',
  'Launching isolated Playwright browser context...',
  'Opening URL — no cookies, no history, no exposure...',
  'Collecting HTTP response headers...',
  'Enumerating loaded scripts...',
  'Reading cookie metadata via browser API...',
  'Scanning inline JS for dangerous patterns...',
  'Checking for mixed HTTP/HTTPS content...',
  'Running phishing URL pattern analysis...',
  'Cross-referencing known malicious domain list...',
  'Computing final risk score...',
];

export default function WarningPage() {
  const [targetUrl, setTargetUrl]   = useState('');
  const [domain, setDomain]         = useState('');
  const [log, setLog]               = useState<string[]>([]);
  const [result, setResult]         = useState<ScanResult | null>(null);
  const [scanning, setScanning]     = useState(true);
  const [autoTimer, setAutoTimer]   = useState<number | null>(null);
  const [countdown, setCountdown]   = useState(0);
  const logRef = useRef<HTMLDivElement>(null);
  const stepRef = useRef(0);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const pushLog = (line: string) => {
    setLog(prev => [...prev, line]);
    setTimeout(() => {
      if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
    }, 30);
  };

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const url = params.get('url') || '';
    if (!url) { setScanning(false); return; }

    setTargetUrl(url);
    try { setDomain(new URL(url).hostname); } catch { setDomain(url); }

    pushLog(`SANDBOX> navigation intercepted`);
    pushLog(`SANDBOX> target: ${url}`);

    // Stream log steps while scan runs in parallel
    intervalRef.current = setInterval(() => {
      if (stepRef.current < SCAN_STEPS.length) {
        pushLog(`SANDBOX> ${SCAN_STEPS[stepRef.current]}`);
        stepRef.current++;
      } else {
        if (intervalRef.current) clearInterval(intervalRef.current);
      }
    }, 350);

    // Run real scan
    fetch('/api/sandbox-scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    })
      .then(r => r.json())
      .then(data => {
        if (intervalRef.current) clearInterval(intervalRef.current);
        // Flush remaining steps instantly
        for (let i = stepRef.current; i < SCAN_STEPS.length; i++) {
          pushLog(`SANDBOX> ${SCAN_STEPS[i]}`);
        }

        if (data.success && data.result) {
          const r: ScanResult = data.result;
          pushLog(`SANDBOX> ─────────────────────────────`);
          pushLog(`SANDBOX> scripts_found:       ${r.scriptsCount}`);
          pushLog(`SANDBOX> cookies_found:       ${r.cookiesCount}`);
          pushLog(`SANDBOX> mixed_content:       ${r.mixedContent}`);
          pushLog(`SANDBOX> suspicious_patterns: ${r.suspiciousPatterns?.length ?? 0}`);
          pushLog(`SANDBOX> risk_score:          ${r.riskScore} / 100`);
          pushLog(`SANDBOX> security_score:      ${r.securityScore} / 100`);
          pushLog(`SANDBOX> threats_found:       ${r.threats.length}`);
          pushLog(`SANDBOX> ─────────────────────────────`);

          if (r.sandboxVerdict === 'block') {
            pushLog(`SANDBOX> ⛔ VERDICT: BLOCK — site is unsafe`);
          } else if (r.sandboxVerdict === 'warning') {
            pushLog(`SANDBOX> ⚠  VERDICT: WARNING — proceed with caution`);
          } else {
            pushLog(`SANDBOX> ✓  VERDICT: SAFE — no critical issues found`);
          }

          setResult(r);
          setScanning(false);

          // Auto-proceed for safe sites after 4 seconds
          if (r.sandboxVerdict === 'safe') {
            setCountdown(4);
            let c = 4;
            const t = window.setInterval(() => {
              c--;
              setCountdown(c);
              if (c <= 0) {
                window.clearInterval(t);
                proceed(url);
              }
            }, 1000);
            setAutoTimer(t as unknown as number);
          }
        } else {
          pushLog(`SANDBOX> error: scan API returned failure`);
          setScanning(false);
        }
      })
      .catch(() => {
        if (intervalRef.current) clearInterval(intervalRef.current);
        pushLog(`SANDBOX> error: could not reach scan API`);
        setScanning(false);
      });

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []); // eslint-disable-line

  const proceed = (url?: string) => {
    const dest = url || targetUrl;
    if (!dest) return;
    if (autoTimer) window.clearInterval(autoTimer);
    // Navigate via the proceed API — it adds to bypass set then redirects
    window.location.href = `/api/proceed?url=${encodeURIComponent(dest)}`;
  };

  const goBack = () => {
    if (autoTimer) window.clearInterval(autoTimer);
    window.history.back();
  };

  const CIRC = 2 * Math.PI * 36;
  const color = result ? verdictColor(result.sandboxVerdict) : '#00eaff';

  return (
    <div style={{
      minHeight: '100vh', background: '#050505',
      fontFamily: "'JetBrains Mono','Fira Code',monospace",
      color: '#e5e7eb', display: 'flex', flexDirection: 'column',
    }}>
      {/* Top bar */}
      <div style={{
        background: '#0a0a0a', borderBottom: `2px solid ${color}`,
        padding: '10px 20px', display: 'flex', alignItems: 'center',
        justifyContent: 'space-between', flexShrink: 0,
      }}>
        <div>
          <span style={{ fontSize: 13, fontWeight: 700, color, letterSpacing: '0.12em', textShadow: `0 0 10px ${color}` }}>
            AI-NMS // SANDBOX INTERCEPTOR
          </span>
          <div style={{ fontSize: 10, color: '#374151', marginTop: 2 }}>
            {scanning ? '● SCANNING IN ISOLATED CONTEXT...' : result ? `● SCAN COMPLETE — ${result.sandboxVerdict.toUpperCase()}` : '● READY'}
          </div>
        </div>
        <div style={{ fontSize: 10, color: '#374151', textAlign: 'right' }}>
          <div>{domain || '...'}</div>
          <div style={{ fontSize: 9, marginTop: 2 }}>
            {scanning ? 'analyzing...' : result ? `risk: ${result.riskScore}/100` : ''}
          </div>
        </div>
      </div>

      <div style={{ flex: 1, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 0, overflow: 'hidden' }}>

        {/* LEFT — Sandbox execution log */}
        <div style={{ borderRight: '1px solid #1f2937', display: 'flex', flexDirection: 'column' }}>
          <div style={{ padding: '8px 16px', borderBottom: '1px solid #1f2937', background: '#0a0a0a', flexShrink: 0 }}>
            <span style={{ fontSize: 9, color: '#374151', letterSpacing: '0.1em' }}>
              // SANDBOX_EXECUTION_LOG
            </span>
            {scanning && (
              <span style={{ marginLeft: 12, fontSize: 9, color: '#00eaff' }}>● RUNNING</span>
            )}
          </div>
          <div
            ref={logRef}
            style={{ flex: 1, overflowY: 'auto', padding: '12px 16px', fontSize: 11, lineHeight: 1.9 }}
          >
            {log.map((line, i) => (
              <div key={i} style={{
                color: line.includes('⛔') || line.includes('error') ? '#ff3b3b'
                     : line.includes('⚠') ? '#facc15'
                     : line.includes('✓') ? '#00ff88'
                     : line.includes('─') ? '#1f2937'
                     : line.includes('risk_score') || line.includes('threats_found') ? '#e5e7eb'
                     : '#6b7280',
              }}>
                {line}
                {i === log.length - 1 && scanning && (
                  <span style={{ display: 'inline-block', width: 8, height: 14, background: '#00eaff', marginLeft: 4, verticalAlign: 'middle', animation: 'blink 0.8s step-end infinite' }} />
                )}
              </div>
            ))}
          </div>
        </div>

        {/* RIGHT — Result + actions */}
        <div style={{ display: 'flex', flexDirection: 'column' }}>

          {/* Scanning state */}
          {scanning && (
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 16, padding: 32 }}>
              <div style={{ width: 60, height: 60, border: '3px solid #1f2937', borderTop: `3px solid #00eaff`, borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
              <div style={{ fontSize: 12, color: '#00eaff', letterSpacing: '0.1em' }}>SCANNING IN SANDBOX</div>
              <div style={{ fontSize: 10, color: '#374151', textAlign: 'center', maxWidth: 260, lineHeight: 1.6 }}>
                This site is being analyzed in an isolated Playwright browser.
                Your real browser has not loaded it yet.
              </div>
              <div style={{ fontSize: 10, color: '#374151', border: '1px solid #1f2937', padding: '6px 14px' }}>
                {domain}
              </div>
            </div>
          )}

          {/* Result state */}
          {!scanning && result && (
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflowY: 'auto' }}>

              {/* Score + verdict */}
              <div style={{ padding: 20, borderBottom: '1px solid #1f2937', background: '#0a0a0a' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                  {/* Ring */}
                  <div style={{ position: 'relative', width: 80, height: 80, flexShrink: 0 }}>
                    <svg width="80" height="80" viewBox="0 0 80 80" style={{ transform: 'rotate(-90deg)' }}>
                      <circle cx="40" cy="40" r="36" fill="none" stroke="#111827" strokeWidth="5" />
                      <circle cx="40" cy="40" r="36" fill="none"
                        stroke={scoreColor(result.securityScore)} strokeWidth="5"
                        strokeDasharray={`${(result.securityScore / 100) * CIRC * 1.11} ${CIRC * 1.11}`}
                        style={{ filter: `drop-shadow(0 0 4px ${scoreColor(result.securityScore)})` }}
                      />
                    </svg>
                    <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                      <span style={{ fontSize: 22, fontWeight: 700, color: scoreColor(result.securityScore), textShadow: `0 0 10px ${scoreColor(result.securityScore)}` }}>
                        {result.securityScore}
                      </span>
                      <span style={{ fontSize: 7, color: '#374151' }}>SCORE</span>
                    </div>
                  </div>

                  <div>
                    <div style={{
                      fontSize: 12, fontWeight: 700, color,
                      border: `1px solid ${color}`, padding: '3px 12px',
                      display: 'inline-block', letterSpacing: '0.12em', marginBottom: 8,
                      textShadow: `0 0 8px ${color}`,
                    }}>
                      {result.sandboxVerdict === 'block' ? '⛔ BLOCKED' : result.sandboxVerdict === 'warning' ? '⚠ WARNING' : '✓ SAFE'}
                      {' — '}{riskLabel(result.riskScore)}
                    </div>
                    <div style={{ fontSize: 11, color: '#00eaff' }}>{result.domain}</div>
                    <div style={{ fontSize: 10, color: '#374151', marginTop: 4 }}>
                      risk {result.riskScore}/100 &nbsp;·&nbsp; {result.threats.length} threat{result.threats.length !== 1 ? 's' : ''} &nbsp;·&nbsp; {result.scriptsCount} scripts &nbsp;·&nbsp; {result.cookiesCount} cookies
                    </div>
                  </div>
                </div>
              </div>

              {/* Threats list */}
              <div style={{ flex: 1, overflowY: 'auto', padding: '8px 16px' }}>
                <div style={{ fontSize: 9, color: '#374151', letterSpacing: '0.1em', marginBottom: 8 }}>
                  // SANDBOX_FINDINGS [{result.threats.length}]
                </div>
                {result.threats.length === 0 ? (
                  <div style={{ color: '#00ff88', fontSize: 11, padding: '16px 0', textAlign: 'center' }}>
                    ✓ No threats detected — site appears secure
                  </div>
                ) : result.threats.map((t, i) => (
                  <div key={i} style={{ display: 'flex', gap: 8, padding: '5px 0', borderBottom: '1px solid #111827', alignItems: 'flex-start' }}>
                    <span style={{
                      fontSize: 8, fontWeight: 700, padding: '1px 5px',
                      background: levelColor(t.level), color: '#000',
                      flexShrink: 0, marginTop: 2,
                    }}>
                      {t.level.toUpperCase()}
                    </span>
                    <span style={{ fontSize: 10.5, color: '#9ca3af', lineHeight: 1.4 }}>{t.text}</span>
                  </div>
                ))}

                {/* Recommendations */}
                {result.recommendations.length > 0 && (
                  <div style={{ marginTop: 12 }}>
                    <div style={{ fontSize: 9, color: '#374151', letterSpacing: '0.08em', marginBottom: 6 }}>// AI_RECOMMENDATIONS</div>
                    {result.recommendations.slice(0, 3).map((r, i) => (
                      <div key={i} style={{ fontSize: 10, color: '#9ca3af', display: 'flex', gap: 6, padding: '2px 0' }}>
                        <span style={{ color: '#00eaff', flexShrink: 0 }}>AI&gt;</span><span>{r}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Action buttons */}
              <div style={{ padding: '14px 16px', borderTop: '1px solid #1f2937', background: '#0a0a0a', display: 'flex', gap: 8, flexShrink: 0 }}>
                <button
                  onClick={goBack}
                  style={{
                    flex: 1, padding: '10px 0',
                    background: result.sandboxVerdict === 'block' ? '#ff3b3b' : 'transparent',
                    border: `1px solid ${result.sandboxVerdict === 'block' ? '#ff3b3b' : '#374151'}`,
                    color: result.sandboxVerdict === 'block' ? '#000' : '#9ca3af',
                    fontFamily: 'inherit', fontSize: 10, fontWeight: 700,
                    cursor: 'pointer', letterSpacing: '0.08em',
                  }}
                >
                  [ GO BACK ]
                </button>

                <button
                  onClick={() => proceed()}
                  style={{
                    flex: 2, padding: '10px 0',
                    background: result.sandboxVerdict === 'safe' ? '#00ff88' : 'transparent',
                    border: `1px solid ${result.sandboxVerdict === 'safe' ? '#00ff88' : color}`,
                    color: result.sandboxVerdict === 'safe' ? '#000' : color,
                    fontFamily: 'inherit', fontSize: 10, fontWeight: 700,
                    cursor: 'pointer', letterSpacing: '0.08em',
                  }}
                >
                  {result.sandboxVerdict === 'safe'
                    ? `[ PROCEED${countdown > 0 ? ` (${countdown})` : ''} ]`
                    : result.sandboxVerdict === 'warning'
                      ? '[ PROCEED ANYWAY — I UNDERSTAND THE RISK ]'
                      : '[ PROCEED ANYWAY — IGNORE WARNING ]'}
                </button>
              </div>
            </div>
          )}

          {/* Error / no URL state */}
          {!scanning && !result && (
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#374151', fontSize: 11 }}>
              No URL provided or scan failed.
            </div>
          )}
        </div>
      </div>

      <style>{`
        @keyframes spin  { to { transform: rotate(360deg); } }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
        ::-webkit-scrollbar { width: 3px }
        ::-webkit-scrollbar-thumb { background: #1f2937 }
        * { box-sizing: border-box; margin: 0; padding: 0; }
      `}</style>
    </div>
  );
}
