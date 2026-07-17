// ============================================================
// SENTINEL THREAT FORECAST API
// Analyzes last 5 minutes of traffic for attack patterns.
// Returns: probability, predicted attack type, ETA.
// ============================================================

import { NextResponse } from 'next/server';
import store from '@/lib/sessionStore';
import Groq from 'groq-sdk';

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

interface ForecastResult {
  timestamp:     string;
  threatLevel:   'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  probability:   number;         // 0-100
  predictedType: string;         // 'DDoS' | 'BruteForce' | etc.
  etaMinutes:    number | null;  // estimated time to peak attack
  reasoning:     string;
  signals:       { signal: string; weight: number }[];
  trend:         'escalating' | 'stable' | 'declining';
  // Time-series for chart
  timeSeries:    { time: string; riskScore: number; requestCount: number }[];
}

function detectPatterns(traffic: ReturnType<typeof store.getTraffic>) {
  const now   = Date.now();
  const fiveMinAgo = now - 5 * 60 * 1000;
  const recent = traffic.filter(t => new Date(t.timestamp).getTime() > fiveMinAgo);

  if (recent.length === 0) {
    return { patterns: [], recent, avgRisk: 0 };
  }

  const patterns: { signal: string; weight: number }[] = [];
  const avgRisk = recent.reduce((s, t) => s + (t.riskScore ?? 0), 0) / recent.length;

  // ── Spike detection ──
  const twoMinAgo = now - 2 * 60 * 1000;
  const lastTwo   = recent.filter(t => new Date(t.timestamp).getTime() > twoMinAgo);
  const prevThree = recent.filter(t => new Date(t.timestamp).getTime() <= twoMinAgo);
  if (prevThree.length > 0 && lastTwo.length > prevThree.length * 1.5) {
    patterns.push({ signal: 'Request volume spike (>50% increase in last 2 min)', weight: 35 });
  }

  // ── DDoS pre-signature ──
  const uniqueIPs = new Set(recent.map(t => t.ip)).size;
  if (uniqueIPs > 10 && recent.length > 20) {
    patterns.push({ signal: `Multi-source flood: ${uniqueIPs} unique IPs in 5 min`, weight: 40 });
  }

  // ── Brute force warmup ──
  const ipCounts: Record<string, number> = {};
  recent.forEach(t => { ipCounts[t.ip] = (ipCounts[t.ip] ?? 0) + 1; });
  const topIP     = Object.entries(ipCounts).sort((a, b) => b[1] - a[1])[0];
  if (topIP && topIP[1] > 8) {
    patterns.push({ signal: `Repeated requests from ${topIP[0]}: ${topIP[1]} times`, weight: 30 });
  }

  // ── Port scan reconnaissance ──
  const portVariety = new Set(recent.map(t => t.port)).size;
  if (portVariety > 10) {
    patterns.push({ signal: `Port scan activity: ${portVariety} unique ports probed`, weight: 25 });
  }

  // ── Escalating risk trend ──
  const half = Math.floor(recent.length / 2);
  const firstHalfAvg  = recent.slice(half).reduce((s, t) => s + (t.riskScore ?? 0), 0) / (recent.length - half || 1);
  const secondHalfAvg = recent.slice(0, half).reduce((s, t) => s + (t.riskScore ?? 0), 0) / (half || 1);
  if (secondHalfAvg > firstHalfAvg * 1.3) {
    patterns.push({ signal: 'Risk score escalating over last 5 minutes', weight: 20 });
  }

  return { patterns, recent, avgRisk };
}

function buildTimeSeries(traffic: ReturnType<typeof store.getTraffic>) {
  // Bucket into 30s intervals over last 5 minutes
  const now     = Date.now();
  const buckets: Record<number, { total: number; count: number; requests: number }> = {};

  for (let i = 0; i < 10; i++) {
    buckets[i] = { total: 0, count: 0, requests: 0 };
  }

  traffic.forEach(t => {
    const age = now - new Date(t.timestamp).getTime();
    if (age > 5 * 60 * 1000) return;
    const bucket = Math.floor(age / 30000);
    if (bucket < 10) {
      buckets[bucket].total    += t.riskScore ?? 0;
      buckets[bucket].count++;
      buckets[bucket].requests += t.requestCount ?? 1;
    }
  });

  return Array.from({ length: 10 }, (_, i) => {
    const b   = buckets[9 - i]; // reverse so oldest is first
    const sec = (9 - i) * 30;
    return {
      time:         `-${Math.floor(sec / 60)}m${sec % 60}s`,
      riskScore:    b.count > 0 ? Math.round(b.total / b.count) : 0,
      requestCount: b.requests,
    };
  });
}

export async function GET() {
  try {
    const traffic  = store.getTraffic(200);
    const { patterns, recent, avgRisk } = detectPatterns(traffic);
    const timeSeries = buildTimeSeries(traffic);

    // Base probability from local signals
    const baseProb  = Math.min(95, patterns.reduce((s, p) => s + p.weight, 0));
    const trend     = avgRisk > 50 ? 'escalating' : avgRisk > 25 ? 'stable' : 'declining';

    // Classify predicted attack type
    let predictedType = 'Unknown';
    if (patterns.some(p => p.signal.includes('Multi-source')))    predictedType = 'DDoS';
    else if (patterns.some(p => p.signal.includes('Repeated')))   predictedType = 'Brute Force';
    else if (patterns.some(p => p.signal.includes('Port scan')))  predictedType = 'Port Scan';
    else if (patterns.some(p => p.signal.includes('spike')))      predictedType = 'Volumetric Attack';

    const threatLevel: ForecastResult['threatLevel'] =
      baseProb >= 75 ? 'CRITICAL' :
      baseProb >= 50 ? 'HIGH' :
      baseProb >= 25 ? 'MEDIUM' : 'LOW';

    const etaMinutes = baseProb >= 50
      ? Math.round(Math.max(1, (100 - baseProb) / 10))
      : null;

    // ── LLM enrichment for reasoning ──────────────────────────
    let reasoning = patterns.length === 0
      ? 'No significant attack patterns detected in the last 5 minutes.'
      : `${patterns.length} threat signal(s) detected suggesting ${predictedType} activity.`;

    if (process.env.GROQ_API_KEY && patterns.length > 0) {
      try {
        const completion = await groq.chat.completions.create({
          model:       'llama-3.3-70b-versatile',
          temperature: 0.2,
          max_tokens:  200,
          messages: [{
            role:    'user',
            content: `You are a threat forecasting AI. Analyze these network security signals from the last 5 minutes and provide a 1-sentence forecast.

Signals detected:
${patterns.map(p => `- ${p.signal} (weight: ${p.weight})`).join('\n')}
Average risk score: ${Math.round(avgRisk)}/100
Traffic volume: ${recent.length} packets
Trend: ${trend}

Respond with exactly one sentence predicting the threat.`,
          }],
        });
        reasoning = completion.choices[0]?.message?.content?.trim() ?? reasoning;
      } catch {}
    }

    const result: ForecastResult = {
      timestamp:     new Date().toISOString(),
      threatLevel,
      probability:   baseProb,
      predictedType: patterns.length === 0 ? 'None' : predictedType,
      etaMinutes,
      reasoning,
      signals:       patterns,
      trend,
      timeSeries,
    };

    return NextResponse.json({ success: true, forecast: result });
  } catch (err) {
    console.error('[Forecast] Error:', err);
    return NextResponse.json({ success: false, error: 'Forecast unavailable' }, { status: 500 });
  }
}
