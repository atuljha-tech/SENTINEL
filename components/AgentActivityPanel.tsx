'use client';

import { useState, useEffect } from 'react';

interface AgentKey {
  key: string; agentId: string; tier: string; createdAt: string; label: string;
}
interface Metrics {
  totalKeys: number; activeKeys: number; callsToday: number;
  callsMonth: number; mrrUsd: number;
  tierBreakdown: { free: number; pro: number; team: number; enterprise: number };
  topTools: { tool: string; count: number }[];
}

const TIER_PRICES: Record<string, number> = { free: 0, pro: 29, team: 99, enterprise: 0 };
const TIER_COLORS: Record<string, string> = {
  free: 'var(--muted)', pro: 'var(--cyan)', team: 'var(--purple)', enterprise: 'var(--yellow)',
};

const CODE_EXAMPLE = `// 5 lines to protect any AI agent
const res = await fetch('https://sentinel.vercel.app/api/v1/agent/clearance', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    agentId:  'my-trading-bot',
    url:      suspiciousUrl,
    context:  'about to approve token swap',
    agentKey: 'sk-sentinel-xxxx',
  })
});

const { clearanceGranted, reason, auditId } = await res.json();
if (!clearanceGranted) throw new Error(\`Blocked: \${reason}\`);`;

export default function AgentActivityPanel() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [keys,    setKeys]    = useState<AgentKey[]>([]);
  const [tab,     setTab]     = useState<'metrics' | 'keys' | 'api'>('metrics');
  const [testing, setTesting] = useState(false);
  const [testUrl, setTestUrl] = useState('https://example.com');
  const [testResult, setTestResult] = useState<any>(null);

  useEffect(() => {
    fetch('/api/usage').then(r => r.json()).then(d => {
      if (d.success) { setMetrics(d.metrics); setKeys(d.keys ?? []); }
    }).catch(() => {});
  }, []);

  const runTest = async () => {
    setTesting(true); setTestResult(null);
    try {
      const res = await fetch('/api/v1/agent/clearance', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentId: 'demo-agent', url: testUrl, context: 'demo test', agentKey: 'sk-sentinel-demo0000' }),
      });
      const data = await res.json();
      setTestResult(data);
    } catch (e: any) { setTestResult({ error: e.message }); }
    setTesting(false);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Tab bar */}
      <div className="t-panel">
        <div className="t-panel-header">
          <span className="t-panel-title">AGENT_SERVICE_API</span>
          <div style={{ display: 'flex', gap: 6 }}>
            {(['metrics', 'keys', 'api'] as const).map(t => (
              <button key={t} className={`t-btn ${tab === t ? 'primary' : 'ghost'}`} style={{ fontSize: 9, padding: '2px 10px' }} onClick={() => setTab(t)}>
                {t.toUpperCase()}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Metrics tab */}
      {tab === 'metrics' && metrics && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 1, background: 'var(--border)', border: '1px solid var(--border)', borderRadius: 4, overflow: 'hidden' }}>
            {[
              { label: 'TOTAL KEYS',   value: metrics.totalKeys,   color: 'var(--cyan)' },
              { label: 'ACTIVE KEYS',  value: metrics.activeKeys,  color: 'var(--green)' },
              { label: 'CALLS TODAY',  value: metrics.callsToday,  color: 'var(--yellow)' },
              { label: 'MRR (USD)',    value: `$${metrics.mrrUsd}`,color: 'var(--purple)' },
            ].map(m => (
              <div key={m.label} style={{ background: 'var(--bg2)', padding: '16px' }}>
                <div style={{ fontSize: 9, color: 'var(--faint)', letterSpacing: '0.1em', marginBottom: 6 }}>{m.label}</div>
                <div style={{ fontSize: 24, fontWeight: 700, color: m.color }}>{m.value}</div>
              </div>
            ))}
          </div>

          <div className="t-grid-2">
            <div className="t-panel">
              <div className="t-panel-header"><span className="t-panel-title">TIER_BREAKDOWN</span></div>
              <div className="t-panel-body">
                {Object.entries(metrics.tierBreakdown).map(([tier, count]) => (
                  <div key={tier} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                    <span style={{ fontSize: 9, color: TIER_COLORS[tier], width: 80, fontWeight: 700 }}>{tier.toUpperCase()}</span>
                    <div style={{ flex: 1 }}>
                      <div style={{ background: 'var(--bg4)', height: 4, borderRadius: 2 }}>
                        <div style={{ background: TIER_COLORS[tier], height: 4, borderRadius: 2, width: `${(count / Math.max(metrics.totalKeys, 1)) * 100}%`, transition: 'width 0.7s' }} />
                      </div>
                    </div>
                    <span style={{ fontSize: 12, fontWeight: 700, color: TIER_COLORS[tier], width: 24, textAlign: 'right' }}>{count}</span>
                    {tier !== 'free' && tier !== 'enterprise' && <span style={{ fontSize: 9, color: 'var(--faint)', width: 40 }}>${TIER_PRICES[tier]}/mo</span>}
                  </div>
                ))}
              </div>
            </div>
            <div className="t-panel">
              <div className="t-panel-header"><span className="t-panel-title">TOP_TOOLS_USED</span></div>
              <div className="t-panel-body">
                {metrics.topTools.length === 0
                  ? <div style={{ color: 'var(--faint)', fontSize: 11 }}>// No tool usage yet</div>
                  : metrics.topTools.map((t, i) => (
                    <div key={t.tool} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                      <span style={{ fontSize: 9, color: 'var(--faint)', width: 16 }}>{i + 1}.</span>
                      <span style={{ flex: 1, fontSize: 11, color: 'var(--cyan)' }}>{t.tool}</span>
                      <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--yellow)' }}>{t.count}</span>
                    </div>
                  ))
                }
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Keys tab */}
      {tab === 'keys' && (
        <div className="t-panel">
          <div className="t-panel-header">
            <span className="t-panel-title">AGENT_KEYS</span>
            <span className="t-panel-meta">{keys.length} KEYS</span>
          </div>
          <table className="t-table">
            <thead><tr><th>KEY</th><th>AGENT ID</th><th>LABEL</th><th>TIER</th><th>CREATED</th></tr></thead>
            <tbody>
              {keys.map(k => (
                <tr key={k.key}>
                  <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--faint)', fontSize: 10 }}>{k.key.slice(0, 24)}...</td>
                  <td style={{ color: 'var(--cyan)' }}>{k.agentId}</td>
                  <td>{k.label}</td>
                  <td><span className="t-tag" style={{ color: TIER_COLORS[k.tier], borderColor: TIER_COLORS[k.tier] }}>{k.tier.toUpperCase()}</span></td>
                  <td className="t-td-time">{new Date(k.createdAt).toLocaleDateString()}</td>
                </tr>
              ))}
              {keys.length === 0 && <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--faint)', padding: 20 }}>// No keys yet</td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {/* API Demo tab */}
      {tab === 'api' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div className="t-panel">
            <div className="t-panel-header"><span className="t-panel-title">AGENT_CLEARANCE_API</span><span className="t-panel-meta">POST /api/v1/agent/clearance</span></div>
            <div className="t-panel-body">
              <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 12, lineHeight: 1.6 }}>
                Any OKX.AI agent can call this endpoint before navigating to a URL or approving a transaction.
                Returns <span style={{ color: 'var(--green)' }}>clearanceGranted</span>, risk score, and a Civic audit ID.
              </div>
              <pre className="api-code-block" style={{ overflowX: 'auto' }}>
                <code style={{ whiteSpace: 'pre' }}>{CODE_EXAMPLE}</code>
              </pre>
            </div>
          </div>

          {/* Live test */}
          <div className="t-panel">
            <div className="t-panel-header"><span className="t-panel-title">LIVE_API_TEST</span></div>
            <div className="t-panel-body">
              <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
                <input
                  value={testUrl}
                  onChange={e => setTestUrl(e.target.value)}
                  placeholder="Enter URL to test..."
                  style={{ flex: 1, background: 'var(--bg3)', border: '1px solid var(--border)', color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 11, padding: '8px 12px', outline: 'none', borderRadius: 4 }}
                />
                <button className="t-btn primary" onClick={runTest} disabled={testing} style={{ whiteSpace: 'nowrap' }}>
                  {testing ? 'SCANNING...' : 'TEST CLEARANCE →'}
                </button>
              </div>
              {testResult && (
                <div className="t-slide-up" style={{ background: 'var(--bg3)', border: `1px solid ${testResult.clearanceGranted ? 'var(--green)' : 'var(--red)'}`, borderRadius: 4, padding: 14 }}>
                  <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 8 }}>
                    <span style={{ fontSize: 13, fontWeight: 700, color: testResult.clearanceGranted ? 'var(--green)' : 'var(--red)' }}>
                      {testResult.clearanceGranted ? '✓ CLEARANCE GRANTED' : '⛔ CLEARANCE DENIED'}
                    </span>
                    {testResult.riskScore !== undefined && (
                      <span style={{ fontSize: 11, color: 'var(--muted)' }}>Risk: {testResult.riskScore}/100</span>
                    )}
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--muted)', marginBottom: 4 }}>
                    <strong style={{ color: 'var(--cyan)' }}>Reason:</strong> {testResult.reason}
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--muted)', marginBottom: 4 }}>
                    <strong style={{ color: 'var(--cyan)' }}>Suggested Action:</strong> <span style={{ color: 'var(--yellow)' }}>{testResult.suggestedAction}</span>
                  </div>
                  {testResult.auditId && (
                    <div style={{ fontSize: 10, color: 'var(--faint)' }}>
                      <strong>Audit ID:</strong> {testResult.auditId}
                    </div>
                  )}
                  {testResult.error && <div style={{ color: 'var(--red)', fontSize: 10 }}>{testResult.error}</div>}
                </div>
              )}
            </div>
          </div>

          {/* Pricing */}
          <div className="t-panel">
            <div className="t-panel-header"><span className="t-panel-title">PRICING_TIERS</span></div>
            <div className="t-panel-body">
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
                {[
                  { tier: 'Free', price: '$0', scans: '50 scans/mo', keys: '1 key', color: 'var(--muted)' },
                  { tier: 'Pro', price: '$29/mo', scans: '500 scans/mo', keys: '5 keys', color: 'var(--cyan)' },
                  { tier: 'Team', price: '$99/mo', scans: '5,000 scans/mo', keys: '25 keys', color: 'var(--purple)' },
                  { tier: 'Enterprise', price: 'Custom', scans: 'Unlimited', keys: 'Unlimited', color: 'var(--yellow)' },
                ].map(p => (
                  <div key={p.tier} style={{ background: 'var(--bg3)', border: `1px solid ${p.color}30`, borderRadius: 6, padding: 14 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: p.color, marginBottom: 4 }}>{p.tier}</div>
                    <div style={{ fontSize: 18, fontWeight: 700, color: '#fff', marginBottom: 8 }}>{p.price}</div>
                    <div style={{ fontSize: 10, color: 'var(--muted)', lineHeight: 1.7 }}>
                      <div>· {p.scans}</div>
                      <div>· {p.keys}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
