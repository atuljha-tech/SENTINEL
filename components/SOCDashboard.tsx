'use client';

import { useState, useEffect, useRef } from 'react';
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  AreaChart, Area, ReferenceLine, Dot,
} from 'recharts';

interface SOCDashboardProps {
  traffic: any[];
  stats: any[];
  alerts: any[];
  blockedIPs: any[];
}

// ── Theme colours ──────────────────────────────────────────────
const CLR = {
  green:   '#00ff88',
  yellow:  '#facc15',
  red:     '#ff3b3b',
  cyan:    '#00eaff',
  orange:  '#f97316',
  purple:  '#a855f7',
  grid:    '#1f2937',
  axis:    '#4b5563',
  bg:      '#0a0a0a',
  surface: '#111827',
};

// ── Custom tooltip ─────────────────────────────────────────────
function CustomTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: '#050505', border: '1px solid #1f2937',
      borderLeft: `2px solid ${CLR.cyan}`,
      padding: '8px 12px', fontSize: 11,
      fontFamily: "'JetBrains Mono', monospace",
    }}>
      <div style={{ color: CLR.cyan, marginBottom: 4, fontSize: 10 }}>{label}</div>
      {payload.map((p: any, i: number) => (
        <div key={i} style={{ color: p.color, display: 'flex', gap: 8, alignItems: 'center' }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: p.color, display: 'inline-block', flexShrink: 0 }} />
          <span style={{ color: '#9ca3af' }}>{p.name}:</span>
          <span style={{ color: p.color, fontWeight: 700 }}>{p.value}</span>
        </div>
      ))}
    </div>
  );
}

// ── Custom dot with glow ───────────────────────────────────────
function GlowDot(props: any) {
  const { cx, cy, fill } = props;
  if (!cx || !cy) return null;
  return (
    <g>
      <circle cx={cx} cy={cy} r={5} fill={CLR.bg} stroke={fill} strokeWidth={2} />
      <circle cx={cx} cy={cy} r={3} fill={fill} />
    </g>
  );
}

// ── Pie label ─────────────────────────────────────────────────
function PieLabel({ cx, cy, midAngle, outerRadius, name, percent, value }: any) {
  if (!percent || percent < 0.06 || !value) return null;
  const RADIAN = Math.PI / 180;
  const r = outerRadius + 22;
  const x = cx + r * Math.cos(-midAngle * RADIAN);
  const y = cy + r * Math.sin(-midAngle * RADIAN);
  return (
    <text x={x} y={y} fill="#9ca3af" textAnchor={x > cx ? 'start' : 'end'}
      dominantBaseline="central" fontSize={10} fontFamily="'JetBrains Mono', monospace">
      {name} {(percent * 100).toFixed(0)}%
    </text>
  );
}

export default function SOCDashboard({ traffic, stats, alerts, blockedIPs }: SOCDashboardProps) {
  const [chartData,    setChartData]    = useState<any[]>([]);
  const [attackData,   setAttackData]   = useState<any[]>([]);
  const [riskData,     setRiskData]     = useState<any[]>([]);
  const [topAttackers, setTopAttackers] = useState<any[]>([]);
  const [animated,     setAnimated]     = useState(false);
  const prevLen = useRef(0);

  useEffect(() => {
    if (!traffic?.length) return;

    // Trigger re-animation when new data arrives
    if (traffic.length !== prevLen.current) {
      setAnimated(false);
      setTimeout(() => setAnimated(true), 50);
      prevLen.current = traffic.length;
    }

    // Traffic over time — last 20 entries, oldest first
    const last20 = [...traffic].slice(0, 20).reverse();
    setChartData(last20.map(t => ({
      time:     new Date(t.timestamp).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      requests: t.requestCount ?? 0,
      risk:     t.riskScore ?? 0,
    })));

    // Attack distribution
    const attackCounts: Record<string, number> = {};
    alerts.forEach(a => {
      const type = a.attackType ?? 'Unknown';
      attackCounts[type] = (attackCounts[type] ?? 0) + 1;
    });
    setAttackData(
      Object.entries(attackCounts)
        .sort((a, b) => b[1] - a[1])
        .map(([name, value]) => ({ name, value }))
    );

    // Risk distribution
    const safe   = traffic.filter(t => (t.riskScore ?? 0) < 35).length;
    const medium = traffic.filter(t => (t.riskScore ?? 0) >= 35 && (t.riskScore ?? 0) < 70).length;
    const high   = traffic.filter(t => (t.riskScore ?? 0) >= 70).length;
    setRiskData([
      { name: 'Safe',   value: safe,   color: CLR.green  },
      { name: 'Medium', value: medium, color: CLR.yellow },
      { name: 'High',   value: high,   color: CLR.red    },
    ]);

    // Top attackers
    const map = new Map<string, any>();
    alerts.forEach(a => {
      const ip = a.trafficData?.ip;
      if (ip && (!map.has(ip) || map.get(ip).risk < a.riskScore)) {
        map.set(ip, { ip, risk: a.riskScore, type: a.attackType });
      }
    });
    setTopAttackers(Array.from(map.values()).sort((a, b) => b.risk - a.risk).slice(0, 5));
  }, [traffic, alerts]);

  const totalSafe   = riskData.find(r => r.name === 'Safe')?.value   ?? 0;
  const totalMedium = riskData.find(r => r.name === 'Medium')?.value ?? 0;
  const totalHigh   = riskData.find(r => r.name === 'High')?.value   ?? 0;
  const total       = totalSafe + totalMedium + totalHigh;

  const panelStyle: React.CSSProperties = {
    background: CLR.bg,
    border: `1px solid ${CLR.grid}`,
    padding: '16px 18px',
  };

  const titleStyle: React.CSSProperties = {
    fontSize: 10, fontWeight: 700, letterSpacing: '0.1em',
    color: CLR.cyan, marginBottom: 14,
    fontFamily: "'JetBrains Mono', monospace",
    borderBottom: `1px solid ${CLR.grid}`, paddingBottom: 8,
  };

  const emptyStyle: React.CSSProperties = {
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    height: 280, color: '#374151', fontSize: 11,
    fontFamily: "'JetBrains Mono', monospace",
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>

      {/* Row 1: Traffic area chart + Threat pie */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1 }}>

        {/* Real-time Traffic */}
        <div style={panelStyle}>
          <div style={titleStyle}>// REAL_TIME_TRAFFIC_ANALYSIS</div>
          {chartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <AreaChart data={chartData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="gReq" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor={CLR.cyan}  stopOpacity={0.25} />
                    <stop offset="95%" stopColor={CLR.cyan}  stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gRisk" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor={CLR.red}   stopOpacity={0.25} />
                    <stop offset="95%" stopColor={CLR.red}   stopOpacity={0} />
                  </linearGradient>
                  <filter id="glow">
                    <feGaussianBlur stdDeviation="2" result="blur" />
                    <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
                  </filter>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={CLR.grid} vertical={false} />
                <XAxis
                  dataKey="time"
                  stroke={CLR.axis}
                  tick={{ fill: '#4b5563', fontSize: 9, fontFamily: "'JetBrains Mono', monospace" }}
                  tickLine={false}
                  axisLine={{ stroke: CLR.grid }}
                  interval="preserveStartEnd"
                />
                <YAxis
                  stroke={CLR.axis}
                  tick={{ fill: '#4b5563', fontSize: 9, fontFamily: "'JetBrains Mono', monospace" }}
                  tickLine={false}
                  axisLine={{ stroke: CLR.grid }}
                  width={32}
                  tickFormatter={(v) => String(v)}
                />
                <Tooltip content={<CustomTooltip />} />
                <Legend
                  wrapperStyle={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: '#6b7280', paddingTop: 8 }}
                />
                <Area
                  type="monotone" dataKey="requests" name="Requests"
                  stroke={CLR.cyan} strokeWidth={2}
                  fill="url(#gReq)"
                  dot={<GlowDot fill={CLR.cyan} />}
                  activeDot={{ r: 6, fill: CLR.cyan, stroke: CLR.bg, strokeWidth: 2 }}
                  isAnimationActive={animated}
                  animationDuration={800}
                  animationEasing="ease-out"
                />
                <Area
                  type="monotone" dataKey="risk" name="Risk Score"
                  stroke={CLR.red} strokeWidth={2}
                  fill="url(#gRisk)"
                  dot={<GlowDot fill={CLR.red} />}
                  activeDot={{ r: 6, fill: CLR.red, stroke: CLR.bg, strokeWidth: 2 }}
                  isAnimationActive={animated}
                  animationDuration={800}
                  animationEasing="ease-out"
                />
                {/* Reference line at risk threshold 35 */}
                <ReferenceLine y={35} stroke={CLR.yellow} strokeDasharray="4 4"
                  label={{ value: 'WARN', fill: CLR.yellow, fontSize: 8, fontFamily: 'monospace' }} />
                <ReferenceLine y={70} stroke={CLR.red} strokeDasharray="4 4"
                  label={{ value: 'CRIT', fill: CLR.red, fontSize: 8, fontFamily: 'monospace' }} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div style={emptyStyle}>// awaiting traffic data...</div>
          )}
        </div>

        {/* Threat Level Distribution */}
        <div style={panelStyle}>
          <div style={titleStyle}>// THREAT_LEVEL_DISTRIBUTION</div>
          {total > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={240}>
                <PieChart>
                  <Pie
                    data={riskData.filter(d => d.value > 0)}
                    cx="50%" cy="50%"
                    innerRadius={55} outerRadius={90}
                    paddingAngle={3}
                    dataKey="value"
                    labelLine={false}
                    label={PieLabel}
                    isAnimationActive={animated}
                    animationBegin={0}
                    animationDuration={900}
                    animationEasing="ease-out"
                  >
                    {riskData.filter(d => d.value > 0).map((entry, i) => (
                      <Cell key={i} fill={entry.color}
                        stroke={CLR.bg} strokeWidth={3}
                        style={{ filter: `drop-shadow(0 0 6px ${entry.color}80)` }}
                      />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                </PieChart>
              </ResponsiveContainer>
              {/* Legend */}
              <div style={{ display: 'flex', justifyContent: 'center', gap: 20, marginTop: 4 }}>
                {[
                  { label: 'SAFE',   val: totalSafe,   color: CLR.green  },
                  { label: 'MEDIUM', val: totalMedium, color: CLR.yellow },
                  { label: 'HIGH',   val: totalHigh,   color: CLR.red    },
                ].map(l => (
                  <div key={l.label} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: l.color, display: 'inline-block', boxShadow: `0 0 6px ${l.color}` }} />
                    <span style={{ fontSize: 9, color: '#6b7280', fontFamily: 'monospace' }}>{l.label}: <span style={{ color: l.color }}>{l.val}</span></span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div style={emptyStyle}>// no threat data yet...</div>
          )}
        </div>
      </div>

      {/* Row 2: Attack vector bar + Top attackers */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1 }}>

        {/* Attack Vector Analysis */}
        <div style={panelStyle}>
          <div style={titleStyle}>// ATTACK_VECTOR_ANALYSIS</div>
          {attackData.length > 0 ? (
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={attackData} layout="vertical" margin={{ top: 0, right: 16, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={CLR.grid} horizontal={false} />
                <XAxis
                  type="number"
                  stroke={CLR.axis}
                  tick={{ fill: '#4b5563', fontSize: 9, fontFamily: 'monospace' }}
                  tickLine={false}
                  axisLine={{ stroke: CLR.grid }}
                  allowDecimals={false}
                />
                <YAxis
                  type="category" dataKey="name"
                  stroke={CLR.axis}
                  tick={{ fill: '#9ca3af', fontSize: 9, fontFamily: 'monospace' }}
                  tickLine={false}
                  axisLine={false}
                  width={110}
                />
                <Tooltip content={<CustomTooltip />} />
                <Bar
                  dataKey="value" name="Count"
                  radius={[0, 4, 4, 0]}
                  isAnimationActive={animated}
                  animationDuration={700}
                  animationEasing="ease-out"
                >
                  {attackData.map((entry, i) => {
                    const colors = [CLR.red, CLR.orange, CLR.yellow, CLR.cyan, CLR.purple];
                    return <Cell key={i} fill={colors[i % colors.length]}
                      style={{ filter: `drop-shadow(0 0 4px ${colors[i % colors.length]}60)` }} />;
                  })}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div style={emptyStyle}>// no attacks detected yet...</div>
          )}
        </div>

        {/* Most Active Threat Actors */}
        <div style={panelStyle}>
          <div style={titleStyle}>// MOST_ACTIVE_THREAT_ACTORS</div>
          {topAttackers.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 260, overflowY: 'auto' }}>
              {topAttackers.map((a, i) => {
                const barColor = a.risk >= 70 ? CLR.red : a.risk >= 50 ? CLR.orange : CLR.yellow;
                return (
                  <div key={i} style={{ background: '#111827', padding: '10px 12px', borderLeft: `2px solid ${barColor}` }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                      <span style={{ fontFamily: 'monospace', fontSize: 11, color: CLR.cyan }}>{a.ip}</span>
                      <span style={{ fontSize: 9, fontWeight: 700, padding: '1px 6px', background: barColor, color: '#000' }}>
                        RISK:{a.risk}
                      </span>
                    </div>
                    <div style={{ fontSize: 9, color: '#6b7280', marginBottom: 6 }}>{a.type}</div>
                    <div style={{ background: '#1f2937', height: 3, borderRadius: 2 }}>
                      <div style={{
                        height: 3, borderRadius: 2,
                        width: `${a.risk}%`,
                        background: barColor,
                        boxShadow: `0 0 6px ${barColor}`,
                        transition: 'width 0.6s ease',
                      }} />
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={emptyStyle}>// no threat actors detected...</div>
          )}
        </div>
      </div>

      {/* Row 3: Summary metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 1 }}>
        {[
          { label: 'TOTAL_PACKETS', value: traffic.length,    color: CLR.cyan   },
          { label: 'ACTIVE_ALERTS', value: alerts.length,     color: alerts.length > 0 ? CLR.red : CLR.green },
          { label: 'BLOCKED_IPS',   value: blockedIPs.length, color: blockedIPs.length > 0 ? CLR.orange : CLR.green },
          { label: 'SAFE_TRAFFIC',  value: totalSafe,         color: CLR.green  },
          { label: 'SECURITY_%',    value: total > 0 ? `${Math.round((totalSafe / total) * 100)}%` : '100%', color: CLR.green },
        ].map(m => (
          <div key={m.label} style={{ background: CLR.bg, border: `1px solid ${CLR.grid}`, padding: '12px 14px', textAlign: 'center' }}>
            <div style={{ fontSize: 18, fontWeight: 700, color: m.color, textShadow: `0 0 8px ${m.color}60`, fontFamily: 'monospace' }}>
              {m.value}
            </div>
            <div style={{ fontSize: 8, color: '#374151', marginTop: 4, letterSpacing: '0.08em', fontFamily: 'monospace' }}>
              {m.label}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
