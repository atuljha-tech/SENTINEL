'use client';

import { useState } from 'react';

type AttackType = 'ddos' | 'bruteforce' | 'portscan';

interface SimResult {
  attack: string;
  generatedTraffic: number;
  alertsTriggered: number;
  maxRiskScore: number;
}

interface AttackConfig {
  type: AttackType;
  label: string;
  desc: string;
  color: string;
  icon: string;
  detail: string;
}

const ATTACKS: AttackConfig[] = [
  {
    type:   'ddos',
    label:  'SIMULATE DDoS',
    desc:   'Distributed Denial of Service',
    color:  'var(--red)',
    icon:   '⚡',
    detail: '20 IPs · 100–200 req each · port 80',
  },
  {
    type:   'bruteforce',
    label:  'SIMULATE BRUTE FORCE',
    desc:   'Credential stuffing attack',
    color:  'var(--yellow)',
    icon:   '🔑',
    detail: '15 rapid bursts · same IP · port 443',
  },
  {
    type:   'portscan',
    label:  'SIMULATE PORT SCAN',
    desc:   'Network reconnaissance',
    color:  'var(--cyan)',
    icon:   '🔍',
    detail: '10 dangerous ports · single IP',
  },
];

function riskColor(score: number) {
  if (score >= 70) return 'var(--red)';
  if (score >= 35) return 'var(--yellow)';
  return 'var(--green)';
}

export default function AttackSimulator() {
  const [running,  setRunning]  = useState<AttackType | null>(null);
  const [result,   setResult]   = useState<SimResult | null>(null);
  const [error,    setError]    = useState('');
  const [history,  setHistory]  = useState<SimResult[]>([]);

  const simulate = async (type: AttackType) => {
    setRunning(type);
    setResult(null);
    setError('');

    try {
      const res = await fetch('/api/simulate-attack', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ type }),
      });
      const data = await res.json();

      if (data.success) {
        const r: SimResult = {
          attack:           data.attack,
          generatedTraffic: data.generatedTraffic,
          alertsTriggered:  data.alertsTriggered,
          maxRiskScore:     data.maxRiskScore,
        };
        setResult(r);
        setHistory(prev => [r, ...prev].slice(0, 5));
      } else {
        setError(data.error ?? 'Simulation failed');
      }
    } catch {
      setError('Cannot reach server — is npm run dev running?');
    } finally {
      setRunning(null);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <div style={{ fontSize: 10, color: 'var(--cyan)', letterSpacing: '0.1em', fontWeight: 700 }}>
            // ATTACK_SIMULATOR
          </div>
          <div style={{ fontSize: 10, color: 'var(--faint)', marginTop: 2 }}>
            Simulate real attacks to test the AI detection pipeline
          </div>
        </div>
        <div style={{ fontSize: 9, color: 'var(--faint)', border: '1px solid var(--border)', padding: '2px 8px' }}>
          LIVE PIPELINE
        </div>
      </div>

      {/* Attack buttons */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
        {ATTACKS.map(a => {
          const isRunning = running === a.type;
          return (
            <button
              key={a.type}
              onClick={() => simulate(a.type)}
              disabled={running !== null}
              style={{
                background:   'var(--bg3)',
                borderTop:    `2px solid ${a.color}`,
                borderRight:  `1px solid ${isRunning ? a.color : 'var(--border)'}`,
                borderBottom: `1px solid ${isRunning ? a.color : 'var(--border)'}`,
                borderLeft:   `1px solid ${isRunning ? a.color : 'var(--border)'}`,
                padding:       '12px 10px',
                cursor:        running !== null ? 'not-allowed' : 'pointer',
                opacity:       running !== null && !isRunning ? 0.4 : 1,
                textAlign:     'left',
                transition:    'border-color 0.2s, opacity 0.2s',
                display:       'flex',
                flexDirection: 'column',
                gap:           4,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 14 }}>{a.icon}</span>
                <span style={{
                  fontSize: 9, fontWeight: 700, color: isRunning ? a.color : 'var(--muted)',
                  letterSpacing: '0.08em',
                }}>
                  {isRunning ? 'LAUNCHING...' : a.label}
                </span>
              </div>
              <div style={{ fontSize: 9, color: 'var(--faint)' }}>{a.desc}</div>
              <div style={{ fontSize: 8, color: a.color, marginTop: 2 }}>{a.detail}</div>
              {isRunning && (
                <div style={{ marginTop: 4, height: 2, background: 'var(--border)', borderRadius: 1, overflow: 'hidden' }}>
                  <div style={{
                    height: '100%', background: a.color,
                    animation: 'sim-progress 1.5s ease-in-out infinite',
                    width: '40%',
                  }} />
                </div>
              )}
            </button>
          );
        })}
      </div>

      {/* Result */}
      {result && (
        <div style={{
          background: 'var(--bg3)',
          border: '1px solid var(--border)',
          borderLeft: `3px solid ${riskColor(result.maxRiskScore)}`,
          padding: '10px 14px',
        }}>
          <div style={{ fontSize: 9, color: 'var(--faint)', letterSpacing: '0.1em', marginBottom: 8 }}>
            // SIMULATION_COMPLETE
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8 }}>
            {[
              { label: 'ATTACK_TYPE',    value: result.attack.toUpperCase(),       color: 'var(--cyan)' },
              { label: 'TRAFFIC_GEN',    value: `${result.generatedTraffic} req`,  color: 'var(--muted)' },
              { label: 'ALERTS_FIRED',   value: String(result.alertsTriggered),    color: result.alertsTriggered > 0 ? 'var(--red)' : 'var(--green)' },
              { label: 'MAX_RISK',       value: `${result.maxRiskScore}/100`,      color: riskColor(result.maxRiskScore) },
            ].map(m => (
              <div key={m.label}>
                <div style={{ fontSize: 8, color: 'var(--faint)', letterSpacing: '0.08em', marginBottom: 2 }}>{m.label}</div>
                <div style={{ fontSize: 14, fontWeight: 700, color: m.color, textShadow: `0 0 8px ${m.color}60` }}>{m.value}</div>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 8, fontSize: 9, color: 'var(--faint)' }}>
            ↑ Check TRAFFIC LOGS and THREAT ANALYSIS tabs for live results
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div style={{ fontSize: 10, color: 'var(--red)', border: '1px solid var(--red)', padding: '6px 10px' }}>
          ✗ {error}
        </div>
      )}

      {/* History */}
      {history.length > 0 && (
        <div>
          <div style={{ fontSize: 9, color: 'var(--faint)', letterSpacing: '0.08em', marginBottom: 6 }}>
            // SIMULATION_HISTORY
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {history.map((h, i) => (
              <div key={i} style={{ display: 'flex', gap: 12, fontSize: 9, color: 'var(--faint)', padding: '3px 0', borderBottom: '1px solid var(--border)' }}>
                <span style={{ color: 'var(--cyan)', width: 80 }}>{h.attack.toUpperCase()}</span>
                <span>{h.generatedTraffic} req</span>
                <span style={{ color: h.alertsTriggered > 0 ? 'var(--red)' : 'var(--green)' }}>{h.alertsTriggered} alerts</span>
                <span style={{ color: riskColor(h.maxRiskScore) }}>risk:{h.maxRiskScore}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <style>{`
        @keyframes sim-progress {
          0%   { transform: translateX(-100%); }
          100% { transform: translateX(350%); }
        }
      `}</style>
    </div>
  );
}
