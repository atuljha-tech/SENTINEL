'use client';

import { useState, useRef, useEffect, useCallback } from 'react';

// ── Types ──────────────────────────────────────────────
interface SandboxThreat {
  level: 'low' | 'medium' | 'high' | 'critical';
  text: string;
}
interface SandboxResult {
  url: string;
  domain: string;
  riskScore: number;
  securityScore: number;
  threats: SandboxThreat[];
  sandboxVerdict: 'safe' | 'warning' | 'block';
  recommendations: string[];
  scriptsCount: number;
  cookiesCount: number;
  mixedContent: number;
  suspiciousPatterns: string[];
  timestamp: string;
}

const DEMO_URLS = [
  'https://github.com',
  'https://example.com',
  'http://login-verify-account.com',
  'https://paypal-secure-login.com',
  'https://wikipedia.org',
];

function levelColor(l: string) {
  if (l === 'critical') return '#ff3b3b';
  if (l === 'high')     return '#f97316';
  if (l === 'medium')   return '#facc15';
  return '#00eaff';
}
function verdictColor(v: string) {
  if (v === 'block')   return '#ff3b3b';
  if (v === 'warning') return '#facc15';
  return '#00ff88';
}
function scoreColor(s: number) {
  if (s >= 80) return '#00ff88';
  if (s >= 60) return '#facc15';
  if (s >= 40) return '#f97316';
  return '#ff3b3b';
}
function riskLabel(r: number) {
  if (r >= 80) return 'CRITICAL';
  if (r >= 60) return 'HIGH RISK';
  if (r >= 35) return 'WARNING';
  return 'SAFE';
}

// ── Interactive Browser Component ──────────────────────
function InteractiveBrowser({ initialUrl }: { initialUrl: string }) {
  const canvasRef   = useRef<HTMLCanvasElement>(null);
  const wsRef       = useRef<WebSocket | null>(null);
  const [connected, setConnected]   = useState(false);
  const [status,    setStatus]      = useState('Not connected');
  const [liveUrl,   setLiveUrl]     = useState(initialUrl);
  const [navInput,  setNavInput]    = useState(initialUrl);
  const [serverUp,  setServerUp]    = useState<boolean | null>(null);

  // Check if sandbox server is running (local only — not available on Vercel)
  useEffect(() => {
    // On Vercel the sandbox server doesn't exist — skip the check
    const sandboxOrigin = process.env.NEXT_PUBLIC_SANDBOX_URL || 'http://localhost:4000';
    fetch(`${sandboxOrigin}/health`)
      .then(r => r.json())
      .then(() => setServerUp(true))
      .catch(() => setServerUp(false));
  }, []);

  const connect = useCallback((url: string) => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setStatus('Connecting to sandbox server...');
    const sandboxWsUrl = process.env.NEXT_PUBLIC_SANDBOX_WS_URL || 'ws://localhost:4000';
    const ws = new WebSocket(sandboxWsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      setStatus('Connected — launching browser...');
      ws.send(JSON.stringify({ type: 'start', url }));
    };

    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type === 'frame') {
        setLiveUrl(msg.url || url);
        setNavInput(msg.url || url);
        setStatus('');
        const canvas = canvasRef.current;
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;
        const img = new Image();
        img.onload = () => {
          canvas.width  = img.width;
          canvas.height = img.height;
          ctx.drawImage(img, 0, 0);
        };
        img.src = 'data:image/jpeg;base64,' + msg.data;
      } else if (msg.type === 'status') {
        setStatus(msg.message);
      } else if (msg.type === 'error') {
        setStatus('Error: ' + msg.message);
      }
    };

    ws.onclose = () => {
      setConnected(false);
      setStatus('Disconnected from sandbox server');
    };

    ws.onerror = () => {
      setConnected(false);
      setStatus('Cannot connect to sandbox server — is it running?');
    };
  }, []);

  useEffect(() => {
    return () => { wsRef.current?.close(); };
  }, []);

  // Mouse events → forward to Playwright
  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
    const rect = canvasRef.current!.getBoundingClientRect();
    const scaleX = 1280 / rect.width;
    const scaleY = 720  / rect.height;
    const x = (e.clientX - rect.left) * scaleX;
    const y = (e.clientY - rect.top)  * scaleY;
    wsRef.current.send(JSON.stringify({ type: 'click', x, y }));
  };

  const handleCanvasScroll = (e: React.WheelEvent<HTMLCanvasElement>) => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
    e.preventDefault();
    wsRef.current.send(JSON.stringify({ type: 'scroll', deltaX: e.deltaX, deltaY: e.deltaY }));
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
    e.preventDefault();
    wsRef.current.send(JSON.stringify({ type: 'keydown', key: e.key }));
  };

  const send = (msg: object) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(msg));
    }
  };

  const navigate = () => {
    const dest = navInput.startsWith('http') ? navInput : 'https://' + navInput;
    send({ type: 'navigate', url: dest });
  };

  const borderColor = connected ? '#00ff88' : '#1f2937';

  return (
    <div style={{ background: '#0a0a0a', border: '1px solid #1f2937', borderTop: '2px solid #00eaff', marginTop: 16 }}>
      {/* Section header */}
      <div style={{ padding: '10px 16px', borderBottom: '1px solid #1f2937', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <span style={{ fontSize: 11, fontWeight: 700, color: '#00eaff', letterSpacing: '0.1em' }}>
            INTERACTIVE SANDBOX BROWSER
          </span>
          <span style={{ marginLeft: 12, fontSize: 9, color: connected ? '#00ff88' : '#374151' }}>
            {connected ? '● LIVE' : '● OFFLINE'}
          </span>
        </div>
        <div style={{ fontSize: 9, color: '#374151' }}>
          ISOLATED CHROMIUM // NO COOKIES // NO HISTORY
        </div>
      </div>

      {/* Server not running warning */}
      {serverUp === false && (
        <div style={{ padding: '12px 16px', background: '#ff3b3b10', borderBottom: '1px solid #ff3b3b' }}>
          <div style={{ fontSize: 11, color: '#ff3b3b', marginBottom: 6 }}>
            ⚠ Sandbox server is not running
          </div>
          <div style={{ fontSize: 10, color: '#9ca3af', lineHeight: 1.6 }}>
            Start it in a second terminal:
          </div>
          <div style={{ fontSize: 10, color: '#00eaff', fontFamily: 'monospace', marginTop: 4, padding: '4px 8px', background: '#111', display: 'inline-block' }}>
            npm run sandbox
          </div>
        </div>
      )}

      {/* Browser toolbar */}
      <div style={{ padding: '8px 12px', borderBottom: '1px solid #1f2937', display: 'flex', gap: 6, alignItems: 'center', background: '#0d0d0d' }}>
        <button onClick={() => send({ type: 'back' })}
          disabled={!connected}
          style={{ padding: '4px 10px', background: 'transparent', border: '1px solid #1f2937', color: connected ? '#9ca3af' : '#374151', fontFamily: 'monospace', fontSize: 12, cursor: connected ? 'pointer' : 'not-allowed' }}>
          ←
        </button>
        <button onClick={() => send({ type: 'forward' })}
          disabled={!connected}
          style={{ padding: '4px 10px', background: 'transparent', border: '1px solid #1f2937', color: connected ? '#9ca3af' : '#374151', fontFamily: 'monospace', fontSize: 12, cursor: connected ? 'pointer' : 'not-allowed' }}>
          →
        </button>
        <button onClick={() => send({ type: 'reload' })}
          disabled={!connected}
          style={{ padding: '4px 10px', background: 'transparent', border: '1px solid #1f2937', color: connected ? '#9ca3af' : '#374151', fontFamily: 'monospace', fontSize: 12, cursor: connected ? 'pointer' : 'not-allowed' }}>
          ↺
        </button>
        <input
          value={navInput}
          onChange={e => setNavInput(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') navigate(); }}
          style={{ flex: 1, background: '#111', border: '1px solid #1f2937', color: '#9ca3af', fontFamily: 'monospace', fontSize: 11, padding: '4px 10px', outline: 'none' }}
        />
        <button onClick={navigate}
          disabled={!connected}
          style={{ padding: '4px 12px', background: connected ? '#1f2937' : 'transparent', border: '1px solid #1f2937', color: connected ? '#00eaff' : '#374151', fontFamily: 'monospace', fontSize: 10, cursor: connected ? 'pointer' : 'not-allowed' }}>
          GO
        </button>
        {!connected ? (
          <button
            onClick={() => connect(initialUrl || 'https://example.com')}
            style={{ padding: '4px 14px', background: '#00eaff', border: 'none', color: '#000', fontFamily: 'monospace', fontSize: 10, fontWeight: 700, cursor: 'pointer', letterSpacing: '0.06em' }}>
            CONNECT
          </button>
        ) : (
          <button
            onClick={() => { wsRef.current?.close(); setConnected(false); }}
            style={{ padding: '4px 14px', background: 'transparent', border: '1px solid #ff3b3b', color: '#ff3b3b', fontFamily: 'monospace', fontSize: 10, cursor: 'pointer' }}>
            DISCONNECT
          </button>
        )}
      </div>

      {/* Status bar */}
      {status && (
        <div style={{ padding: '4px 12px', fontSize: 9, color: '#374151', borderBottom: '1px solid #111827', background: '#080808' }}>
          {status}
        </div>
      )}

      {/* Canvas — live browser stream */}
      <div
        style={{ position: 'relative', background: '#111', cursor: connected ? 'crosshair' : 'default' }}
        tabIndex={0}
        onKeyDown={handleKeyDown}
      >
        {!connected && (
          <div style={{
            position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
            alignItems: 'center', justifyContent: 'center', gap: 12,
            background: '#0a0a0a', zIndex: 2, minHeight: 400,
          }}>
            <div style={{ fontSize: 32, color: '#1f2937' }}>⬡</div>
            <div style={{ fontSize: 11, color: '#374151', letterSpacing: '0.08em' }}>
              SANDBOX BROWSER OFFLINE
            </div>
            <div style={{ fontSize: 10, color: '#374151', textAlign: 'center', maxWidth: 320, lineHeight: 1.6 }}>
              {serverUp === false
                ? 'Start the sandbox server with: npm run sandbox'
                : 'Click CONNECT to launch an isolated Chromium browser'}
            </div>
            {serverUp !== false && (
              <button
                onClick={() => connect(initialUrl || 'https://example.com')}
                style={{ marginTop: 8, padding: '8px 20px', background: '#00eaff', border: 'none', color: '#000', fontFamily: 'monospace', fontSize: 11, fontWeight: 700, cursor: 'pointer' }}>
                [ LAUNCH SANDBOX BROWSER ]
              </button>
            )}
          </div>
        )}
        <canvas
          ref={canvasRef}
          onClick={handleCanvasClick}
          onWheel={handleCanvasScroll}
          style={{ width: '100%', display: 'block', minHeight: connected ? 'auto' : 400, border: `1px solid ${borderColor}` }}
        />
      </div>

      {/* Footer */}
      <div style={{ padding: '6px 12px', borderTop: '1px solid #111827', display: 'flex', gap: 16, fontSize: 9, color: '#374151' }}>
        <span>ISOLATED CONTEXT</span>
        <span>NO DOWNLOADS</span>
        <span>NO CLIPBOARD</span>
        <span>NO FILE ACCESS</span>
        <span style={{ marginLeft: 'auto', color: connected ? '#00ff88' : '#374151' }}>
          {connected ? `● LIVE — ${liveUrl.slice(0, 60)}` : '● DISCONNECTED'}
        </span>
      </div>
    </div>
  );
}

// ── Main Sandbox Page ──────────────────────────────────
export default function SandboxPage() {
  const [url, setUrl]           = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult]     = useState<SandboxResult | null>(null);
  const [log, setLog]           = useState<string[]>([]);
  const [blocked, setBlocked]   = useState(false);
  const [showBrowser, setShowBrowser] = useState(false);
  const [browserUrl, setBrowserUrl]   = useState('');
  const logRef = useRef<HTMLDivElement>(null);

  const pushLog = (line: string) => {
    setLog(prev => [...prev, line]);
    setTimeout(() => {
      if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
    }, 30);
  };

  const runScan = async (targetUrl?: string) => {
    const scanUrl = (targetUrl ?? url).trim();
    if (!scanUrl) return;
    const fullUrl = scanUrl.startsWith('http') ? scanUrl : 'https://' + scanUrl;

    setScanning(true);
    setResult(null);
    setBlocked(false);
    setLog([]);
    setShowBrowser(false);

    pushLog('SANDBOX> initializing isolated browser context...');
    pushLog('SANDBOX> target: ' + fullUrl);
    pushLog('SANDBOX> launching Playwright headless Chromium...');

    const steps = [
      'SANDBOX> intercepting navigation request...',
      'SANDBOX> opening URL in isolated context (no cookies, no history)...',
      'SANDBOX> collecting HTTP response headers...',
      'SANDBOX> enumerating loaded scripts...',
      'SANDBOX> reading cookie metadata via browser API...',
      'SANDBOX> scanning inline JS for dangerous patterns...',
      'SANDBOX> checking for mixed HTTP/HTTPS content...',
      'SANDBOX> running phishing URL pattern analysis...',
      'SANDBOX> cross-referencing known malicious domain list...',
      'SANDBOX> computing risk score...',
    ];

    let i = 0;
    const interval = setInterval(() => {
      if (i < steps.length) { pushLog(steps[i]); i++; }
      else clearInterval(interval);
    }, 400);

    try {
      const res = await fetch('/api/sandbox-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: fullUrl }),
      });
      const data = await res.json();
      clearInterval(interval);

      if (data.success && data.result) {
        const r: SandboxResult = data.result;
        pushLog('SANDBOX> scan complete in isolated context');
        pushLog('SANDBOX> scripts_found: ' + r.scriptsCount);
        pushLog('SANDBOX> cookies_found: ' + r.cookiesCount);
        pushLog('SANDBOX> mixed_content: ' + r.mixedContent);
        pushLog('SANDBOX> suspicious_patterns: ' + (r.suspiciousPatterns?.length ?? 0));
        pushLog('SANDBOX> risk_score: ' + r.riskScore);
        pushLog('SANDBOX> verdict: ' + r.sandboxVerdict.toUpperCase());

        if (r.sandboxVerdict === 'block') {
          pushLog('SANDBOX> NAVIGATION BLOCKED — site is unsafe');
          setBlocked(true);
        } else if (r.sandboxVerdict === 'warning') {
          pushLog('SANDBOX> WARNING — proceed with caution');
        } else {
          pushLog('SANDBOX> SAFE — no critical issues found');
        }

        setResult(r);
        setBrowserUrl(fullUrl);
      } else {
        pushLog('SANDBOX> error: scan failed');
      }
    } catch {
      clearInterval(interval);
      pushLog('SANDBOX> error: could not reach scan API');
    } finally {
      setScanning(false);
    }
  };

  const CIRC = 2 * Math.PI * 36;

  return (
    <div style={{ minHeight: '100vh', background: '#050505', fontFamily: "'JetBrains Mono','Fira Code',monospace", color: '#e5e7eb', padding: '24px 20px' }}>

      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 20, fontWeight: 700, color: '#00eaff', letterSpacing: '0.12em', textShadow: '0 0 12px #00eaff' }}>
          AI-NMS // SANDBOX SCANNER
        </div>
        <div style={{ fontSize: 11, color: '#374151', marginTop: 4 }}>
          Analyze and interact with any website in an isolated Playwright browser
        </div>
        <a href="/" style={{ fontSize: 10, color: '#374151', textDecoration: 'none', marginTop: 6, display: 'inline-block' }}>
          back to dashboard
        </a>
      </div>

      {/* SECTION 1 — URL Input */}
      <div style={{ background: '#0a0a0a', border: '1px solid #1f2937', borderTop: '2px solid #00eaff', padding: 16, marginBottom: 16 }}>
        <div style={{ fontSize: 9, color: '#374151', letterSpacing: '0.1em', marginBottom: 10 }}>// ENTER_TARGET_URL</div>
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && !scanning) runScan(); }}
            placeholder="https://example.com or paste any URL..."
            style={{ flex: 1, background: '#111', border: '1px solid #1f2937', color: '#00eaff', fontFamily: 'inherit', fontSize: 12, padding: '10px 14px', outline: 'none' }}
          />
          <button
            onClick={() => runScan()}
            disabled={scanning || !url.trim()}
            style={{ padding: '10px 20px', background: scanning ? '#111' : '#00eaff', border: 'none', color: '#000', fontFamily: 'inherit', fontSize: 11, fontWeight: 700, cursor: scanning ? 'not-allowed' : 'pointer', letterSpacing: '0.08em', opacity: scanning ? 0.5 : 1 }}>
            {scanning ? 'SCANNING...' : '[ SCAN ]'}
          </button>
        </div>
        <div style={{ marginTop: 10, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          <span style={{ fontSize: 9, color: '#374151', alignSelf: 'center' }}>QUICK TEST:</span>
          {DEMO_URLS.map(u => (
            <button key={u} onClick={() => { setUrl(u); runScan(u); }}
              style={{ background: 'transparent', border: '1px solid #1f2937', color: u.includes('login-verify') || u.includes('paypal-secure') ? '#ff3b3b' : '#374151', fontFamily: 'inherit', fontSize: 9, padding: '3px 8px', cursor: 'pointer' }}>
              {u.replace('https://', '').replace('http://', '')}
            </button>
          ))}
        </div>
      </div>

      {/* SECTION 2 — Scan Results */}
      <div style={{ display: 'grid', gridTemplateColumns: result ? '1fr 1fr' : '1fr', gap: 12 }}>

        {/* Log */}
        <div style={{ background: '#0a0a0a', border: '1px solid #1f2937' }}>
          <div style={{ padding: '8px 14px', borderBottom: '1px solid #1f2937', display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 10, color: '#00eaff', letterSpacing: '0.1em' }}>SANDBOX_EXECUTION_LOG</span>
            <span style={{ fontSize: 9, color: '#374151' }}>{scanning ? 'RUNNING' : log.length > 0 ? 'COMPLETE' : 'IDLE'}</span>
          </div>
          <div ref={logRef} style={{ padding: '10px 14px', height: 320, overflowY: 'auto', fontSize: 11, lineHeight: 1.8 }}>
            {log.length === 0 ? (
              <div style={{ color: '#374151' }}>
                <div>SANDBOX&gt; ready</div>
                <div>SANDBOX&gt; enter a URL above and click SCAN</div>
                <div>SANDBOX&gt; the site will be opened in an isolated</div>
                <div>SANDBOX&gt; Playwright browser not your real browser</div>
              </div>
            ) : log.map((line, i) => (
              <div key={i} style={{ color: line.includes('BLOCKED') || line.includes('error') ? '#ff3b3b' : line.includes('WARNING') ? '#facc15' : line.includes('SAFE') ? '#00ff88' : '#9ca3af' }}>
                {line}
                {i === log.length - 1 && scanning && <span>_</span>}
              </div>
            ))}
          </div>
        </div>

        {/* Result panel */}
        {result && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{ background: '#0a0a0a', border: '1px solid ' + verdictColor(result.sandboxVerdict), borderTop: '3px solid ' + verdictColor(result.sandboxVerdict), padding: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                <div style={{ position: 'relative', width: 76, height: 76, flexShrink: 0 }}>
                  <svg width="76" height="76" viewBox="0 0 76 76" style={{ transform: 'rotate(-90deg)' }}>
                    <circle cx="38" cy="38" r="36" fill="none" stroke="#111827" strokeWidth="5" />
                    <circle cx="38" cy="38" r="36" fill="none" stroke={scoreColor(result.securityScore)} strokeWidth="5" strokeDasharray={(result.securityScore / 100) * CIRC * 1.04 + ' ' + CIRC * 1.04} />
                  </svg>
                  <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                    <span style={{ fontSize: 20, fontWeight: 700, color: scoreColor(result.securityScore) }}>{result.securityScore}</span>
                    <span style={{ fontSize: 7, color: '#374151' }}>SCORE</span>
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: verdictColor(result.sandboxVerdict), border: '1px solid ' + verdictColor(result.sandboxVerdict), padding: '2px 10px', display: 'inline-block', letterSpacing: '0.12em', marginBottom: 6 }}>
                    {result.sandboxVerdict === 'block' ? 'BLOCKED' : result.sandboxVerdict === 'warning' ? 'WARNING' : 'SAFE'} — {riskLabel(result.riskScore)}
                  </div>
                  <div style={{ fontSize: 11, color: '#00eaff' }}>{result.domain}</div>
                  <div style={{ fontSize: 10, color: '#374151', marginTop: 4 }}>risk: {result.riskScore}/100 | scripts: {result.scriptsCount} | cookies: {result.cookiesCount}</div>
                </div>
              </div>
              {blocked && (
                <div style={{ marginTop: 12, padding: '10px 14px', background: '#ff3b3b15', border: '1px solid #ff3b3b', fontSize: 11, color: '#ff3b3b', lineHeight: 1.6 }}>
                  NAVIGATION BLOCKED — AI-NMS sandbox detected critical threats. Your real browser was never exposed.
                </div>
              )}
              {/* Open in interactive browser button */}
              <button
                onClick={() => setShowBrowser(true)}
                style={{ marginTop: 12, width: '100%', padding: '8px 0', background: 'transparent', border: '1px solid #00eaff', color: '#00eaff', fontFamily: 'inherit', fontSize: 10, fontWeight: 700, cursor: 'pointer', letterSpacing: '0.08em' }}>
                [ OPEN IN INTERACTIVE SANDBOX BROWSER ]
              </button>
            </div>

            <div style={{ background: '#0a0a0a', border: '1px solid #1f2937', flex: 1 }}>
              <div style={{ padding: '8px 14px', borderBottom: '1px solid #1f2937' }}>
                <span style={{ fontSize: 9, color: '#374151', letterSpacing: '0.1em' }}>// SANDBOX_FINDINGS [{result.threats.length}]</span>
              </div>
              <div style={{ padding: '6px 14px', maxHeight: 200, overflowY: 'auto' }}>
                {result.threats.length === 0 ? (
                  <div style={{ color: '#00ff88', fontSize: 11, padding: '12px 0', textAlign: 'center' }}>No threats detected</div>
                ) : result.threats.map((t, i) => (
                  <div key={i} style={{ display: 'flex', gap: 8, padding: '5px 0', borderBottom: '1px solid #111827', alignItems: 'flex-start' }}>
                    <span style={{ fontSize: 8, fontWeight: 700, padding: '1px 5px', background: levelColor(t.level), color: '#000', flexShrink: 0, marginTop: 2 }}>{t.level.toUpperCase()}</span>
                    <span style={{ fontSize: 10.5, color: '#9ca3af', lineHeight: 1.4 }}>{t.text}</span>
                  </div>
                ))}
              </div>
            </div>

            {result.recommendations.length > 0 && (
              <div style={{ background: '#0a0a0a', border: '1px solid #1f2937', padding: '10px 14px' }}>
                <div style={{ fontSize: 9, color: '#374151', letterSpacing: '0.08em', marginBottom: 6 }}>// AI_RECOMMENDATIONS</div>
                {result.recommendations.slice(0, 3).map((r, i) => (
                  <div key={i} style={{ fontSize: 10, color: '#9ca3af', display: 'flex', gap: 6, padding: '2px 0' }}>
                    <span style={{ color: '#00eaff', flexShrink: 0 }}>AI&gt;</span><span>{r}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* SECTION 3 — Interactive Browser */}
      {showBrowser && browserUrl && (
        <InteractiveBrowser initialUrl={browserUrl} />
      )}

      <style>{`
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
        ::-webkit-scrollbar { width: 3px }
        ::-webkit-scrollbar-thumb { background: #1f2937 }
        * { box-sizing: border-box }
      `}</style>
    </div>
  );
}
