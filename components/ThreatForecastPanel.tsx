'use client';

import { useState, useEffect } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface ForecastData {
  timestamp:     string;
  threatLevel:   'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  probability:   number;
  predictedType: string;
  etaMinutes:    number | null;
  reasoning:     string;
  signals:       { signal: string; weight: number }[];
  trend:         'escalating' | 'stable' | 'declining';
  timeSeries:    { time: string; riskScore: number; requestCount: number }[];
}

const LEVEL_COLORS: Record<string, string> = {
  LOW:      'var(--green)',
  MEDIUM:   'var(--yellow)',
  HIGH:     'var(--orange)',
  CRITICAL: 'var(--red)',
};

function CustomTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: '#050810', border: '1px solid var(--border)', padding: '8px 12px', fontSize: 11, fontFamily: 'var(--font-mono)' }}>
      <div style={{ color: 'var(--cyan)', marginBottom: 4, fontSize: 10 }}>{label}</div>
      {payload.map((p: any, i: number) => (
        <div key={i} style={{ color: p.color }}>{p.name}: {p.value}</div>
      ))}
    </div>
  );
}

export default function ThreatForecastPanel() {
  const [forecast, setForecast] = useState<ForecastData | null>(null);
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState('');
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchForecast = async () => {
    setLoading(true); setError('');
    try {
      const res  = await fetch('/api/threat-forecast');
      const data = await res.json();
      if (data.success) setForecast(data.forecast);
      else setError('Forecast unavailable');
    } catch { setError('Failed to reach forecast API'); }
    setLoading(false);
  };

  useEffect(() => {
    fetchForecast();
  }, []);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = setInterval(fetchForecast, 30000);
    return () => clearInterval(t);
  }, [autoRefresh]);

  const levelColor = forecast ? LEVEL_COLORS[forecast.threatLevel] : 'var(--cyan)';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Header */}
      <div className="t-panel">
        <div className="t-panel-header">
          <span className="t-panel-title">PREDICTIVE_THREAT_FORECAST</span>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ fontSize: 9, color: autoRefresh ? 'var(--green)' : 'var(--faint)' }}>
              ● {autoRefresh ? 'AUTO-REFRESH 30s' : 'PAUSED'}
            </span>
            <button className="t-btn ghost" style={{ fontSize: 9, padding: '2px 8px' }} onClick={() => setAutoRefresh(p => !p)}>
              {autoRefresh ? 'PAUSE' : 'RESUME'}
            </button>
            <button className="t-btn primary" style={{ fontSize: 9, padding: '2px 10px' }} onClick={fetchForecast} disabled={loading}>
              {loading ? '⟳' : 'REFRESH'}
            </button>
          </div>
        </div>
      </div>

      {error && <div style={{ padding: 16, background: 'var(--red-dim)', border: '1px solid var(--red)', color: 'var(--red)', fontSize: 11, borderRadius: 4 }}>{error}</div>}

      {loading && !forecast && (
        <div style={{ padding: 48, textAlign: 'center', color: 'var(--faint)', fontSize: 11 }}>
          <div style={{ width: 32, height: 32, border: '2px solid var(--border)', borderTop: '2px solid var(--cyan)', borderRadius: '50%', animation: 'spin 0.8s linear infinite', margin: '0 auto 12px' }} />
          Analyzing traffic patterns...
        </div>
      )}

      {forecast && (
        <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: 12 }}>
          {/* Probability gauge */}
          <div className="t-panel">
            <div className="t-panel-header"><span className="t-panel-title">THREAT_PROBABILITY</span></div>
            <div className="t-panel-body" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: 24, gap: 8 }}>
              <div className={`forecast-prob ${forecast.threatLevel.toLowerCase()}`}>
                {forecast.probability}%
              </div>
              <div style={{ fontSize: 9, color: 'var(--faint)', letterSpacing: '0.1em' }}>PROBABILITY OF ATTACK</div>

              {/* Threat level badge */}
              <div style={{ padding: '4px 16px', border: `1px solid ${levelColor}`, color: levelColor, fontSize: 11, fontWeight: 700, letterSpacing: '0.1em', marginTop: 8, borderRadius: 2 }}>
                {forecast.threatLevel}
              </div>

              {forecast.etaMinutes !== null && (
                <div style={{ marginTop: 8, textAlign: 'center' }}>
                  <div style={{ fontSize: 9, color: 'var(--faint)' }}>ESTIMATED TIME TO PEAK</div>
                  <div style={{ fontSize: 20, fontWeight: 700, color: levelColor }}>{forecast.etaMinutes}m</div>
                </div>
              )}

              <hr className="t-divider" style={{ width: '100%' }} />
              <div style={{ width: '100%', textAlign: 'center' }}>
                <div style={{ fontSize: 9, color: 'var(--faint)', marginBottom: 4 }}>PREDICTED ATTACK TYPE</div>
                <div style={{ color: 'var(--cyan)', fontSize: 13, fontWeight: 700 }}>{forecast.predictedType}</div>
              </div>

              <div style={{ width: '100%', textAlign: 'center', marginTop: 4 }}>
                <div style={{ fontSize: 9, color: 'var(--faint)', marginBottom: 4 }}>TREND</div>
                <div style={{ color: forecast.trend === 'escalating' ? 'var(--red)' : forecast.trend === 'declining' ? 'var(--green)' : 'var(--yellow)', fontSize: 12, fontWeight: 700, textTransform: 'uppercase' }}>
                  {forecast.trend === 'escalating' ? '↑' : forecast.trend === 'declining' ? '↓' : '→'} {forecast.trend}
                </div>
              </div>
            </div>
          </div>

          {/* Right column */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {/* Time series chart */}
            <div className="t-panel">
              <div className="t-panel-header"><span className="t-panel-title">RISK_TREND_5MIN</span></div>
              <div className="t-panel-body">
                <ResponsiveContainer width="100%" height={160}>
                  <AreaChart data={forecast.timeSeries} margin={{ top: 5, right: 10, left: 0, bottom: 0 }}>
                    <defs>
                      <linearGradient id="gRisk" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor={levelColor} stopOpacity={0.3} />
                        <stop offset="95%" stopColor={levelColor} stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                    <XAxis dataKey="time" tick={{ fill: '#4b5563', fontSize: 9, fontFamily: 'monospace' }} tickLine={false} axisLine={{ stroke: 'var(--border)' }} />
                    <YAxis tick={{ fill: '#4b5563', fontSize: 9 }} tickLine={false} axisLine={false} width={28} domain={[0, 100]} />
                    <Tooltip content={<CustomTooltip />} />
                    <Area type="monotone" dataKey="riskScore" name="Risk" stroke={levelColor} strokeWidth={2} fill="url(#gRisk)" dot={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Signals detected */}
            <div className="t-panel">
              <div className="t-panel-header">
                <span className="t-panel-title">THREAT_SIGNALS</span>
                <span className="t-panel-meta">{forecast.signals.length} DETECTED</span>
              </div>
              <div className="t-panel-body" style={{ padding: '8px 14px' }}>
                {forecast.signals.length === 0
                  ? <div style={{ color: 'var(--green)', fontSize: 11 }}>✓ No threat signals detected in the last 5 minutes</div>
                  : forecast.signals.map((s, i) => (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '5px 0', borderBottom: '1px solid var(--border-dim)' }}>
                      <div style={{ width: 40, fontSize: 9, fontWeight: 700, color: s.weight >= 30 ? 'var(--red)' : 'var(--yellow)' }}>W:{s.weight}</div>
                      <div style={{ flex: 1, fontSize: 11, color: 'var(--muted)' }}>{s.signal}</div>
                      <div style={{ width: 80 }}>
                        <div style={{ background: 'var(--bg4)', height: 3, borderRadius: 2 }}>
                          <div style={{ background: s.weight >= 30 ? 'var(--red)' : 'var(--yellow)', height: 3, borderRadius: 2, width: `${(s.weight / 50) * 100}%` }} />
                        </div>
                      </div>
                    </div>
                  ))
                }
              </div>
            </div>

            {/* AI reasoning */}
            <div className="t-panel">
              <div className="t-panel-header"><span className="t-panel-title">AI_REASONING</span><span className="t-panel-meta">GROQ LLM</span></div>
              <div className="t-panel-body" style={{ fontSize: 11, color: 'var(--muted)', lineHeight: 1.7 }}>
                <span style={{ color: 'var(--cyan)' }}>AI&gt;</span> {forecast.reasoning}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
