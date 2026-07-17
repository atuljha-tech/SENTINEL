'use client';

import { useState, useEffect } from 'react';

interface GovLog {
  id: string; timestamp: string; tool: string;
  params: Record<string, unknown>; result: 'allowed' | 'blocked' | 'error';
  reason: string; civicCallId?: string; civicConnected: boolean;
}
interface GovStats {
  block_ip?: number; rate_limit_ip?: number; scan_website?: number;
  log_security_event?: number; retrieve_recent_threats?: number;
}

interface Props {
  logs: GovLog[]; stats: GovStats; revoked: boolean;
  connected: boolean | null;
  onRevoke: () => void; onRefresh: () => void;
}

const TOOL_ICONS: Record<string, string> = {
  block_ip:                '🚫',
  rate_limit_ip:           '⏱',
  scan_website:            '🔍',
  log_security_event:      '📋',
  retrieve_recent_threats: '🛡',
};

function timeAgo(ts: string): string {
  const s = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (s < 60)  return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

function toolColor(tool: string): string {
  if (tool === 'block_ip')           return 'var(--red)';
  if (tool === 'rate_limit_ip')      return 'var(--yellow)';
  if (tool === 'scan_website')       return 'var(--cyan)';
  if (tool === 'log_security_event') return 'var(--muted)';
  return 'var(--purple)';
}

export default function GovernanceFeed({ logs, stats, revoked, connected, onRevoke, onRefresh }: Props) {
  const [filter,   setFilter]   = useState<'all' | 'allowed' | 'blocked' | 'civic'>('all');
  const [search,   setSearch]   = useState('');
  const [selected, setSelected] = useState<GovLog | null>(null);
  const [report,   setReport]   = useState<string>('');
  const [loadingReport, setLoadingReport] = useState(false);

  const filtered = logs.filter(l => {
    if (filter === 'allowed' && l.result !== 'allowed') return false;
    if (filter === 'blocked' && l.result !== 'blocked') return false;
    if (filter === 'civic'   && !l.civicConnected)      return false;
    if (search) {
      const s = search.toLowerCase();
      return (
        l.tool.includes(s) ||
        String(l.params?.ip ?? '').includes(s) ||
        String(l.params?.url ?? '').includes(s) ||
        l.reason.toLowerCase().includes(s)
      );
    }
    return true;
  });

  const generateReport = async (log: GovLog) => {
    setLoadingReport(true);
    try {
      const res = await fetch('/api/civic-audit/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incidentId:  log.id,
          auditId:     log.civicCallId ?? log.id,
          ip:          log.params?.ip,
          threatType:  log.tool,
          riskScore:   log.params?.riskScore ?? 0,
          actions:     [log.result === 'allowed' ? log.tool : 'blocked by guardrail'],
        }),
      });
      const data = await res.json();
      setReport(data.report ?? 'Report unavailable');
    } catch { setReport('Report generation failed'); }
    setLoadingReport(false);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Header bar */}
      <div className="t-panel">
        <div className="t-panel-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span className="t-panel-title">GOVERNANCE_LIVE_FEED</span>
            <span style={{ fontSize: 9, color: 'var(--cyan)', opacity: 0.7 }}>★ HERO VIEW</span>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ fontSize: 9, color: connected === true ? 'var(--green)' : connected === false ? 'var(--red)' : 'var(--faint)' }}>
              ● CIVIC {connected === true ? 'CONNECTED' : connected === false ? 'LOCAL' : 'CHECKING'}
            </span>
            <button className="t-btn danger" style={{ fontSize: 9, padding: '2px 10px' }} onClick={onRevoke}>
              {revoked ? '✓ RESTORE ACCESS' : '⚠ REVOKE ACCESS'}
            </button>
            <button className="t-btn ghost" style={{ fontSize: 9, padding: '2px 10px' }} onClick={onRefresh}>REFRESH</button>
          </div>
        </div>
        <div className="t-panel-body" style={{ padding: '10px 14px' }}>
          {/* Stats row */}
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
            {Object.entries(stats).filter(([, v]) => (v as number) > 0).map(([k, v]) => (
              <div key={k} style={{ background: 'var(--bg3)', border: '1px solid var(--border)', padding: '6px 12px', borderRadius: 4 }}>
                <div style={{ fontSize: 8, color: 'var(--faint)', letterSpacing: '0.08em' }}>{k.replace(/_/g, ' ').toUpperCase()}</div>
                <div style={{ fontSize: 18, fontWeight: 700, color: toolColor(k) }}>{v as number}</div>
              </div>
            ))}
            {Object.keys(stats).length === 0 && <span style={{ fontSize: 11, color: 'var(--faint)' }}>// No tool calls yet — traffic triggers auto-logging</span>}
          </div>
          {/* Filter + search */}
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            {(['all', 'allowed', 'blocked', 'civic'] as const).map(f => (
              <button key={f} className={`t-btn ${filter === f ? 'primary' : 'ghost'}`} style={{ fontSize: 9, padding: '2px 10px' }} onClick={() => setFilter(f)}>
                {f.toUpperCase()}
              </button>
            ))}
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search by IP, URL, tool..."
              style={{ background: 'var(--bg3)', border: '1px solid var(--border)', color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 11, padding: '4px 10px', flex: 1, minWidth: 200, outline: 'none', borderRadius: 4 }}
            />
          </div>
        </div>
      </div>

      {/* Feed + detail pane */}
      <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 360px' : '1fr', gap: 12 }}>
        {/* Main feed */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {filtered.length === 0
            ? <div style={{ padding: 32, textAlign: 'center', color: 'var(--faint)', fontSize: 11, background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 4 }}>
                // No governance events match your filter. Events appear automatically as threats are detected.
              </div>
            : filtered.slice(0, 40).map(log => (
              <div
                key={log.id}
                className={`gov-entry ${log.result}`}
                onClick={() => { setSelected(log); setReport(''); }}
                style={{ cursor: 'pointer' }}
              >
                <div className="gov-entry-header">
                  <span className={`t-tag ${log.result === 'allowed' ? 'green' : log.result === 'blocked' ? 'red' : 'yellow'}`}>
                    {log.result.toUpperCase()}
                  </span>
                  <span style={{ fontSize: 10, color: toolColor(log.tool) }}>
                    {TOOL_ICONS[log.tool] ?? '⚙'} {log.tool}
                  </span>
                  {log.civicConnected && <span className="t-tag cyan">CIVIC HUB</span>}
                  <span style={{ marginLeft: 'auto', fontSize: 9, color: 'var(--faint)' }}>{timeAgo(log.timestamp)}</span>
                </div>
                <div className="gov-entry-chain">
                  <span className="agent">ThreatScoutAgent</span>
                  <span className="arrow">→</span>
                  <span className="tool">{log.tool}</span>
                  <span className="arrow">→</span>
                  <span className="arrow">guardrail {log.result === 'blocked' ? '❌' : '✓'}</span>
                  <span className="arrow">→</span>
                  <span className={log.result === 'allowed' ? 'result-ok' : 'result-bad'}>
                    {log.result === 'allowed' ? 'EXECUTED' : 'BLOCKED'}
                  </span>
                </div>
                <div className="gov-entry-meta">
                  {Boolean(log.params?.ip) && <span>IP: {String(log.params.ip)} · </span>}
                  {log.params?.riskScore !== undefined && <span>Risk: {String(log.params.riskScore)}/100 · </span>}
                  {log.reason}
                  {log.civicCallId && <span style={{ marginLeft: 8 }}>· audit: {log.civicCallId.slice(0, 12)}...</span>}
                </div>
              </div>
            ))
          }
        </div>

        {/* Detail pane */}
        {selected && (
          <div className="t-panel t-slide-up" style={{ alignSelf: 'start', position: 'sticky', top: 52 }}>
            <div className="t-panel-header">
              <span className="t-panel-title">EVENT_DETAIL</span>
              <button className="t-btn ghost" style={{ fontSize: 9 }} onClick={() => setSelected(null)}>✕</button>
            </div>
            <div className="t-panel-body" style={{ fontSize: 11 }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <div><div className="t-label">TOOL</div><div style={{ color: toolColor(selected.tool) }}>{TOOL_ICONS[selected.tool]} {selected.tool}</div></div>
                <div><div className="t-label">RESULT</div><span className={`t-tag ${selected.result === 'allowed' ? 'green' : 'red'}`}>{selected.result.toUpperCase()}</span></div>
                <div><div className="t-label">REASON</div><div style={{ color: 'var(--muted)' }}>{selected.reason}</div></div>
                {Boolean(selected.params?.ip) && <div><div className="t-label">IP</div><div style={{ color: 'var(--cyan)' }}>{String(selected.params.ip)}</div></div>}
                {selected.params?.riskScore !== undefined && <div><div className="t-label">RISK SCORE</div><div style={{ fontWeight: 700, color: 'var(--yellow)' }}>{String(selected.params.riskScore)}/100</div></div>}
                <div><div className="t-label">CIVIC HUB</div><div style={{ color: selected.civicConnected ? 'var(--green)' : 'var(--muted)' }}>{selected.civicConnected ? '✓ Executed on Civic Hub' : 'Local execution (hub unavailable)'}</div></div>
                {selected.civicCallId && <div><div className="t-label">AUDIT ID</div><div style={{ color: 'var(--faint)', fontSize: 10, wordBreak: 'break-all' }}>{selected.civicCallId}</div></div>}
                <div><div className="t-label">TIMESTAMP</div><div style={{ color: 'var(--faint)' }}>{new Date(selected.timestamp).toLocaleString()}</div></div>
                <hr className="t-divider" />
                <button className="t-btn primary" style={{ width: '100%', justifyContent: 'center' }} onClick={() => generateReport(selected)} disabled={loadingReport}>
                  {loadingReport ? '⟳ GENERATING...' : '📋 GENERATE REPORT'}
                </button>
                {report && (
                  <div style={{ background: 'var(--bg3)', border: '1px solid var(--border)', padding: 12, borderRadius: 4, fontSize: 10, color: 'var(--muted)', lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>
                    {report}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
