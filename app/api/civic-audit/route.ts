import { NextRequest, NextResponse } from 'next/server';
import civicHub from '@/lib/civicClient';
import store from '@/lib/sessionStore';

export async function GET(request: NextRequest) {
  try {
    const action = request.nextUrl.searchParams.get('action');

    if (action === 'ping') {
      const connected = await civicHub.ping();
      return NextResponse.json({ success: true, connected });
    }

    if (action === 'tools') {
      const res = await civicHub.listTools();
      return NextResponse.json({ success: res.ok, tools: res.tools ?? [] });
    }

    const limit   = Number(request.nextUrl.searchParams.get('limit') ?? 50);
    const logs    = store.getCivicLogs(limit).map(l => ({ ...l, executedBy: 'AI_AGENT' }));
    const revoked = civicHub.isRevoked();

    // Derive stats from actual log entries (works across serverless instances)
    const allLogs = store.getCivicLogs(500);
    const stats = {
      block_ip:                allLogs.filter(l => l.tool === 'block_ip').length,
      rate_limit_ip:           allLogs.filter(l => l.tool === 'rate_limit_ip').length,
      scan_website:            allLogs.filter(l => l.tool === 'scan_website').length,
      log_security_event:      allLogs.filter(l => l.tool === 'log_security_event').length,
      retrieve_recent_threats: allLogs.filter(l => l.tool === 'retrieve_recent_threats').length,
      log_event:               allLogs.filter(l => l.tool === 'log_security_event').length,
    };

    return NextResponse.json({ success: true, logs, stats, revoked, count: logs.length });
  } catch (err) {
    return NextResponse.json({ success: false, message: 'Failed to fetch audit log' }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();

    if (body.action === 'revoke') {
      civicHub.revoke();
      return NextResponse.json({ success: true, message: 'Tool access revoked', revoked: true });
    }

    if (body.action === 'restore') {
      civicHub.restore();
      return NextResponse.json({ success: true, message: 'Tool access restored', revoked: false });
    }

    if (body.tool && body.params) {
      const result = await civicHub.executeTool(body.tool, body.params);
      // Re-derive stats from logs after the call
      const allLogs = store.getCivicLogs(500);
      const stats = {
        block_ip:                allLogs.filter(l => l.tool === 'block_ip').length,
        rate_limit_ip:           allLogs.filter(l => l.tool === 'rate_limit_ip').length,
        scan_website:            allLogs.filter(l => l.tool === 'scan_website').length,
        log_security_event:      allLogs.filter(l => l.tool === 'log_security_event').length,
        retrieve_recent_threats: allLogs.filter(l => l.tool === 'retrieve_recent_threats').length,
        log_event:               allLogs.filter(l => l.tool === 'log_security_event').length,
      };
      return NextResponse.json({
        success:        result.success,
        auditId:        result.auditId,
        guardrailPassed: result.guardrailPassed,
        reason:         result.reason,
        civicConnected: result.civicConnected,
        stats,
      });
    }

    return NextResponse.json({ success: false, message: 'Unknown action' }, { status: 400 });
  } catch (err) {
    return NextResponse.json({ success: false, message: 'Civic action failed' }, { status: 500 });
  }
}
