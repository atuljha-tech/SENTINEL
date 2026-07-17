import { NextRequest, NextResponse } from 'next/server';
import store from '@/lib/sessionStore';
import { aiDetector } from '@/lib/ai-detection';
import civicHub from '@/lib/civicClient';
import { orchestrate, executeToolCalls } from '@/lib/orchestrator';
import { broadcastUpdate } from '../sandbox-scan/route';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const ip = body.ip || request.headers.get('x-forwarded-for')?.split(',')[0] || 'unknown';

    const entry = store.addTraffic({
      ip,
      port:         body.port         ?? Math.floor(Math.random() * 65535),
      protocol:     body.protocol     ?? 'TCP',
      requestCount: body.requestCount ?? 1,
      userAgent:    request.headers.get('user-agent') ?? 'unknown',
      source:       body.source       ?? 'api',
    });

    // Score with local AI detector
    const allTraffic = store.getTraffic(200) as any[];
    const result = aiDetector.detect(entry as any, allTraffic);

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
        trafficId:    entry.id,
        ip:           entry.ip,
        port:         entry.port,
        protocol:     entry.protocol,
        requestCount: entry.requestCount,
        riskScore:    result.riskScore,
        threatStatus: result.threatStatus,
        attackType:   result.attackType,
        alertFlag:    result.alertFlag,
        reasons:      result.reasons,
        recommendations: result.recommendations,
      });

      // ── LLM Orchestrator for flagged threats (fire-and-forget) ──
      orchestrate({
        ip:          entry.ip,
        port:        entry.port,
        protocol:    entry.protocol,
        requestCount: entry.requestCount,
        riskScore:   result.riskScore,
        threatStatus: result.threatStatus,
        attackType:  result.attackType,
        reasons:     result.reasons,
        source:      body.source ?? 'api',
      }).then(decision => {
        // Execute the orchestrator's tool decisions
        return executeToolCalls(decision, {
          blockIP: (ip, reason) => store.blockIP(ip, reason, result.attackType, result.riskScore),
          civicLog: (event, params) =>
            civicHub.executeTool('log_security_event', { event, ...params }).then(() => {}),
        });
      }).catch(() => {
        // Fallback: direct civic call (original behavior preserved)
        const civicTool = result.riskScore >= 80 ? 'block_ip'
                        : result.riskScore >= 60 ? 'rate_limit_ip'
                        : 'log_security_event';
        civicHub.executeTool(civicTool, {
          ip:         entry.ip,
          attackType: result.attackType,
          riskScore:  result.riskScore,
          reason:     result.reasons[0] ?? result.threatStatus,
          source:     'auto-detection',
        }).catch(() => {});
      });
    }

    broadcastUpdate();
    return NextResponse.json({ success: true, data: { ...entry, ...result }, id: entry.id }, { status: 201 });
  } catch (err) {
    console.error('Traffic POST error:', err);
    return NextResponse.json({ success: false, message: 'Failed to log traffic' }, { status: 500 });
  }
}
export async function GET() {
  try {
    const data = store.getTraffic(100);
    return NextResponse.json({ success: true, data, count: data.length, realTime: true });
  } catch (err) {
    return NextResponse.json({ success: false, message: 'Failed to fetch traffic' }, { status: 500 });
  }
}
