import { NextRequest, NextResponse } from 'next/server';
import store from '@/lib/sessionStore';
import { aiDetector } from '@/lib/ai-detection';
import { broadcastUpdate } from '../sandbox-scan/route';

type AttackType = 'ddos' | 'bruteforce' | 'portscan';

function rand(min: number, max: number) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// ── Traffic entry helper — runs through the full AI pipeline ──
function injectTraffic(ip: string, port: number, protocol: string, requestCount: number, source: string) {
  const allTraffic = store.getTraffic(200) as any[];
  const entry = store.addTraffic({ ip, port, protocol, requestCount, userAgent: 'SimBot/1.0', source });

  const result = aiDetector.detect(entry as any, [...allTraffic, entry as any]);
  store.updateTraffic(entry.id, {
    riskScore:    result.riskScore,
    threatStatus: result.threatStatus,
    attackType:   result.attackType,
    alertFlag:    result.alertFlag,
    analyzedAt:   new Date().toISOString(),
    aiReason:     result.reasons.join(', '),
  });

  if (result.alertFlag) {
    store.addDetection({
      trafficId: entry.id, ip, port, protocol, requestCount,
      riskScore: result.riskScore, threatStatus: result.threatStatus,
      attackType: result.attackType, alertFlag: result.alertFlag,
      reasons: result.reasons, recommendations: result.recommendations,
    });
  }

  return { ip, port, protocol, requestCount, riskScore: result.riskScore, attackType: result.attackType, threatStatus: result.threatStatus };
}

// ── DDoS: 20 IPs, 100–200 requests each, same port ──
function simulateDDoS() {
  const port = 80;
  const generated = [];
  for (let i = 1; i <= 20; i++) {
    const ip = `${rand(1, 254)}.${rand(1, 254)}.${rand(1, 254)}.${i}`;
    generated.push(injectTraffic(ip, port, 'HTTP', rand(100, 200), 'sim-ddos'));
  }
  return generated;
}

// ── Brute Force: same IP, port 443, 60 requests ──
function simulateBruteForce() {
  const ip = '91.200.12.101';
  const generated = [];
  // 15 rapid bursts from same IP — triggers brute force pattern
  for (let i = 0; i < 15; i++) {
    generated.push(injectTraffic(ip, 443, 'HTTPS', rand(4, 8), 'sim-bruteforce'));
  }
  return generated;
}

// ── Port Scan: one IP, multiple dangerous ports ──
function simulatePortScan() {
  const ip = '193.42.56.78';
  const ports = [22, 23, 445, 3389, 1433, 3306, 5900, 6379, 27017, 8080];
  const generated = [];
  for (const port of ports) {
    generated.push(injectTraffic(ip, port, 'TCP', rand(1, 3), 'sim-portscan'));
  }
  return generated;
}

export async function POST(req: NextRequest) {
  try {
    const { type } = await req.json() as { type: AttackType };

    if (!['ddos', 'bruteforce', 'portscan'].includes(type)) {
      return NextResponse.json({ success: false, error: 'Invalid attack type' }, { status: 400 });
    }

    let generated: any[] = [];

    if (type === 'ddos')        generated = simulateDDoS();
    if (type === 'bruteforce')  generated = simulateBruteForce();
    if (type === 'portscan')    generated = simulatePortScan();

    // Broadcast SSE so dashboard updates instantly
    broadcastUpdate();

    const alerts   = generated.filter(e => e.threatStatus !== 'Normal').length;
    const maxRisk  = Math.max(...generated.map(e => e.riskScore));

    return NextResponse.json({
      success: true,
      attack: type,
      generatedTraffic: generated.length,
      alertsTriggered: alerts,
      maxRiskScore: maxRisk,
      entries: generated,
    });
  } catch (err) {
    console.error('simulate-attack error:', err);
    return NextResponse.json({ success: false, error: String(err) }, { status: 500 });
  }
}
