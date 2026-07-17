import { NextRequest, NextResponse } from 'next/server';
import store from '@/lib/sessionStore';
import civicHub from '@/lib/civicClient';
import { retrieveKnowledge } from '@/lib/rag-knowledge';
import { broadcastUpdate } from '../sandbox-scan/route';

function decideAction(riskScore: number, attackType: string, ip: string) {
  if (store.isBlocked(ip))  return { action: 'BLOCK_IP',         reason: `${ip} already blocked`,                               severity: 'High' };
  if (riskScore >= 80)      return { action: 'BLOCK_IP',         reason: `Critical ${attackType} (score ${riskScore})`,         severity: 'Critical' };
  if (riskScore >= 60) {
    if (attackType === 'DDoS')        return { action: 'RATE_LIMIT',        reason: `DDoS from ${ip} — rate limiting`,          severity: 'High' };
    if (attackType === 'Brute Force') return { action: 'CAPTCHA_CHALLENGE', reason: `Brute force from ${ip} — CAPTCHA`,         severity: 'High' };
    return                                   { action: 'BLOCK_IP',         reason: `High-risk ${attackType} from ${ip}`,        severity: 'High' };
  }
  if (riskScore >= 35) {
    if (attackType === 'Port Scan')   return { action: 'RATE_LIMIT',        reason: `Port scan from ${ip} — rate limiting`,     severity: 'Medium' };
    if (attackType === 'Bot Traffic') return { action: 'CAPTCHA_CHALLENGE', reason: `Bot traffic from ${ip} — CAPTCHA`,         severity: 'Medium' };
    return                                   { action: 'ALERT_ONLY',        reason: `Suspicious activity from ${ip}`,           severity: 'Medium' };
  }
  return                                     { action: 'LOG_ONLY',          reason: `Normal traffic from ${ip}`,                severity: 'Low' };
}

// Map internal action names → Civic tool names
function toCivicTool(action: string): string {
  const map: Record<string, string> = {
    BLOCK_IP:          'block_ip',
    RATE_LIMIT:        'rate_limit_ip',
    CAPTCHA_CHALLENGE: 'rate_limit_ip',
    ALERT_ONLY:        'log_security_event',
    LOG_ONLY:          'log_security_event',
  };
  return map[action] ?? 'log_security_event';
}

export async function POST(request: NextRequest) {
  try {
    const { ip, attackType = 'Unknown', riskScore = 0, threatStatus = 'Normal', autoExecute = true } = await request.json();
    if (!ip) return NextResponse.json({ success: false, message: 'IP required' }, { status: 400 });

    const decision   = decideAction(riskScore, attackType, ip);
    const civicTool  = toCivicTool(decision.action);

    // ── Route through Civic Hub ──
    const civic = await civicHub.executeTool(civicTool, {
      ip, attackType, riskScore, reason: decision.reason, severity: decision.severity,
    });

    // ── Execute locally only if Civic allowed it ──
    let executed = false;
    if (civic.guardrailPassed && autoExecute && decision.action === 'BLOCK_IP') {
      store.blockIP(ip, decision.reason, attackType, riskScore);
      executed = true;
    }

    // ── Log response ──
    store.addResponseLog({
      ip, attackType, riskScore, threatStatus,
      action:       decision.action,
      reason:       civic.guardrailPassed ? decision.reason : civic.reason,
      severity:     decision.severity,
      autoExecuted: executed,
    });

    const knowledge = retrieveKnowledge(attackType);

    broadcastUpdate();
    return NextResponse.json({
      success:  civic.guardrailPassed,
      decision: {
        action:       decision.action,
        reason:       decision.reason,
        severity:     decision.severity,
        autoExecuted: executed,
      },
      civic: {
        auditId:         civic.auditId,
        guardrailPassed: civic.guardrailPassed,
        reason:          civic.reason,
        tool:            civicTool,
      },
      recommendations: knowledge?.mitigation.slice(0, 3) ?? ['Monitor the situation'],
    });
  } catch (err) {
    console.error('Respond POST error:', err);
    return NextResponse.json({ success: false, message: 'Failed to execute response' }, { status: 500 });
  }
}

export async function GET(request: NextRequest) {
  try {
    const action = request.nextUrl.searchParams.get('action');
    const ip     = request.nextUrl.searchParams.get('ip');

    if (action === 'unblock' && ip) {
      // Route unblock through Civic too
      await civicHub.executeTool('log_security_event', { event: `unblock_ip`, ip, reason: 'Manual unblock' });
      const ok = store.unblockIP(ip);
      return NextResponse.json({ success: ok, message: ok ? `${ip} unblocked` : `${ip} not found` });
    }

    const logs       = store.getResponseLogs(50).map(l => ({
      _id: l.id, ip: l.ip, attackType: l.attackType, riskScore: l.riskScore,
      timestamp: l.timestamp,
      decision: { action: l.action, reason: l.reason, severity: l.severity },
    }));
    const blockedIPs = store.getBlockedIPs();

    return NextResponse.json({ success: true, logs, blockedIPs, count: logs.length, blockedCount: blockedIPs.length });
  } catch (err) {
    return NextResponse.json({ success: false, message: 'Failed to fetch response data' }, { status: 500 });
  }
}
