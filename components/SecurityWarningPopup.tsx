'use client';

import { useEffect } from 'react';

export interface ScanThreat {
  level: 'low' | 'medium' | 'high' | 'critical';
  text: string;
}

export interface SecurityWarningData {
  url: string;
  domain: string;
  riskScore: number;
  securityScore: number;
  threats: ScanThreat[];
  sandboxVerdict: 'safe' | 'warning' | 'block';
  recommendations: string[];
}

interface Props {
  data: SecurityWarningData;
  onLeave: () => void;
  onProceed: () => void;
  onViewReport: () => void;
}

function severityLabel(risk: number) {
  if (risk >= 80) return { label: 'CRITICAL', color: '#ff3b3b' };
  if (risk >= 60) return { label: 'HIGH RISK', color: '#f97316' };
  if (risk >= 35) return { label: 'WARNING', color: '#facc15' };
  return { label: 'SAFE', color: '#00ff88' };
}

function levelColor(l: string) {
  if (l === 'critical') return '#ff3b3b';
  if (l === 'high')     return '#f97316';
  if (l === 'medium')   return '#facc15';
  return '#00eaff';
}

export default function SecurityWarningPopup({ data, onLeave, onProceed, onViewReport }: Props) {
  const { label, color } = severityLabel(data.riskScore);

  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onLeave(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onLeave]);

  return (
    <div
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.85)',
        zIndex: 9999, display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
      }}
      onClick={e => { if (e.target === e.currentTarget) onLeave(); }}
    >
      <div style={{
        width: 460, maxWidth: '94vw', maxHeight: '90vh',
        background: '#050505', border: `1px solid #1f2937`,
        borderTop: `2px solid ${color}`,
        display: 'flex', flexDirection: 'column', overflow: 'hidden',
        boxShadow: `0 0 60px rgba(0,0,0,0.9), 0 0 20px ${color}20`,
      }}>

        {/* Header */}
        <div style={{ padding: '12px 16px', background: '#0a0a0a', borderBottom: '1px solid #1f2937', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color, letterSpacing: '0.1em', textShadow: `0 0 8px ${color}` }}>
              AI-NMS // SECURITY WARNING
            </div>
            <div style={{ fontSize: 10, color: '#374151', marginTop: 2 }}>{data.domain}</div>
          </div>
          <button onClick={onLeave} style={{ background: 'none', border: '1px solid #1f2937', color: '#374151', width: 24, height: 24, cursor: 'pointer', fontSize: 14, fontFamily: 'monospace' }}>×</button>
        </div>

        {/* Score row */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '14px 16px', borderBottom: '1px solid #1f2937', background: '#0a0a0a' }}>
          <div style={{ position: 'relative', width: 76, height: 76, flexShrink: 0 }}>
            <svg width="76" height="76" viewBox="0 0 76 76" style={{ transform: 'rotate(-90deg)' }}>
              <circle cx="38" cy="38" r="34" fill="none" stroke="#111827" strokeWidth="5" />
              <circle cx="38" cy="38" r="34" fill="none" stroke={color} strokeWidth="5"
                strokeDasharray={`${(data.riskScore / 100) * 213.6} 213.6`} />
            </svg>
            <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <span style={{ fontSize: 20, fontWeight: 700, color, textShadow: `0 0 10px ${color}` }}>{data.riskScore}</span>
              <span style={{ fontSize: 7, color: '#374151' }}>RISK</span>
            </div>
          </div>
          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color, border: `1px solid ${color}`, padding: '2px 8px', display: 'inline-block', letterSpacing: '0.1em', marginBottom: 6 }}>
              {label}
            </div>
            <div style={{ fontSize: 11, color: '#9ca3af', lineHeight: 1.4 }}>
              Sandbox scan detected {data.threats.length} issue{data.threats.length !== 1 ? 's' : ''} on this site.
            </div>
            <div style={{ fontSize: 10, color: '#374151', marginTop: 4 }}>
              {data.url.length > 50 ? data.url.slice(0, 50) + '…' : data.url}
            </div>
          </div>
        </div>

        {/* Threats */}
        {data.threats.length > 0 && (
          <div style={{ flex: 1, overflowY: 'auto', padding: '8px 16px' }}>
            <div style={{ fontSize: 9, color: '#374151', letterSpacing: '0.1em', marginBottom: 6 }}>// DETECTED_ISSUES [{data.threats.length}]</div>
            {data.threats.slice(0, 6).map((t, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: '5px 0', borderBottom: '1px solid #111827' }}>
                <span style={{ fontSize: 8, fontWeight: 700, padding: '1px 5px', background: levelColor(t.level), color: '#000', flexShrink: 0, marginTop: 2 }}>
                  {t.level.toUpperCase()}
                </span>
                <span style={{ fontSize: 10.5, color: '#9ca3af', lineHeight: 1.4 }}>{t.text}</span>
              </div>
            ))}
          </div>
        )}

        {/* Recommendations */}
        {data.recommendations.length > 0 && (
          <div style={{ padding: '8px 16px', borderTop: '1px solid #111827', background: '#0a0a0a' }}>
            <div style={{ fontSize: 9, color: '#374151', letterSpacing: '0.08em', marginBottom: 4 }}>// AI_RECOMMENDATIONS</div>
            {data.recommendations.slice(0, 2).map((r, i) => (
              <div key={i} style={{ fontSize: 9, color: '#9ca3af', display: 'flex', gap: 5, padding: '1px 0' }}>
                <span style={{ color: '#00eaff', flexShrink: 0 }}>AI&gt;</span><span>{r}</span>
              </div>
            ))}
          </div>
        )}

        {/* Actions */}
        <div style={{ display: 'flex', gap: 6, padding: '12px 16px', borderTop: '1px solid #1f2937', background: '#0a0a0a' }}>
          <button onClick={onLeave} style={{
            flex: 1, padding: 8, background: color, border: 'none',
            color: '#000', fontFamily: 'inherit', fontSize: 9, fontWeight: 700,
            cursor: 'pointer', letterSpacing: '0.08em',
          }}>[ LEAVE SITE ]</button>
          <button onClick={onViewReport} style={{
            flex: 1, padding: 8, background: 'transparent', border: `1px solid ${color}`,
            color, fontFamily: 'inherit', fontSize: 9, cursor: 'pointer', letterSpacing: '0.08em',
          }}>[ VIEW REPORT ]</button>
          <button onClick={onProceed} style={{
            padding: '8px 12px', background: 'transparent', border: '1px solid #1f2937',
            color: '#374151', fontFamily: 'inherit', fontSize: 9, cursor: 'pointer',
          }}>[ PROCEED ]</button>
        </div>
      </div>
    </div>
  );
}
