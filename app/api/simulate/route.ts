import { NextResponse } from 'next/server';
import store from '@/lib/sessionStore';
import { aiDetector } from '@/lib/ai-detection';

const MALICIOUS_IPS = ['45.33.22.11', '185.130.5.253', '94.102.61.78', '193.42.56.78', '5.188.86.45'];
const NORMAL_IPS    = ['192.168.1.100', '192.168.1.101', '10.0.0.25', '172.16.0.50', '8.8.8.8', '1.1.1.1'];
const PROTOCOLS     = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'ICMP'];
const ATTACK_PORTS  = [22, 23, 445, 3389, 1433, 3306];
const NORMAL_PORTS  = [80, 443, 8080, 53, 25];

function rand(min: number, max: number) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function pick<T>(arr: T[]): T { return arr[Math.floor(Math.random() * arr.length)]; }

export async function POST() {
  try {
    const allTraffic = store.getTraffic(200) as any[];
    const generated: any[] = [];

    // Generate 4-7 mixed traffic entries — 70% normal, 20% suspicious, 10% attack
    const count = rand(4, 7);
    for (let i = 0; i < count; i++) {
      const roll = Math.random();
      const isAttack    = roll < 0.10;   // 10% attacks
      const isSuspect   = roll < 0.30;   // 20% suspicious (30% - 10%)
      const isMalicious = Math.random() < 0.05; // 5% known malicious IPs

      const ip           = isMalicious ? pick(MALICIOUS_IPS) : isAttack ? `${rand(1,254)}.${rand(1,254)}.${rand(1,254)}.${rand(1,254)}` : pick(NORMAL_IPS);
      const port         = isAttack ? pick(ATTACK_PORTS) : isSuspect ? pick([...ATTACK_PORTS, ...NORMAL_PORTS]) : pick(NORMAL_PORTS);
      const requestCount = isAttack ? rand(80, 200) : isSuspect ? rand(20, 60) : rand(1, 20);
      const protocol     = pick(PROTOCOLS);

      const entry = store.addTraffic({ ip, port, protocol, requestCount, userAgent: isAttack ? 'AutoBot/1.0' : 'Mozilla/5.0', source: 'simulator' });

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

      generated.push({ ip, port, protocol, requestCount, riskScore: result.riskScore, attackType: result.attackType });
    }

    return NextResponse.json({ success: true, generated: generated.length, entries: generated });
  } catch (err) {
    return NextResponse.json({ success: false, error: String(err) });
  }
}
