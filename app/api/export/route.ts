import { NextRequest, NextResponse } from 'next/server';
import store from '@/lib/sessionStore';

export async function GET(request: NextRequest) {
  try {
    const format = request.nextUrl.searchParams.get('format') ?? 'json';

    const traffic     = store.getTraffic(500);
    const alerts      = store.getAlertDetections(200);
    const blockedIPs  = store.getBlockedIPs();
    const responseLogs = store.getResponseLogs(200);
    const websiteScans = store.getWebsiteScans(100);

    const report = {
      generatedAt: new Date().toISOString(),
      summary: {
        totalTraffic:  traffic.length,
        totalAlerts:   alerts.length,
        blockedIPs:    blockedIPs.length,
        websiteScans:  websiteScans.length,
        attackBreakdown: alerts.reduce((acc: Record<string, number>, a) => {
          acc[a.attackType] = (acc[a.attackType] || 0) + 1;
          return acc;
        }, {}),
      },
      traffic:      traffic.map(t => ({ timestamp: t.timestamp, ip: t.ip, port: t.port, protocol: t.protocol, requestCount: t.requestCount, riskScore: t.riskScore, threatStatus: t.threatStatus, attackType: t.attackType })),
      alerts:       alerts.map(a => ({ timestamp: a.timestamp, ip: a.ip, attackType: a.attackType, riskScore: a.riskScore, threatStatus: a.threatStatus, reasons: a.reasons })),
      responseLogs: responseLogs.map(r => ({ timestamp: r.timestamp, ip: r.ip, action: r.action, reason: r.reason, severity: r.severity, attackType: r.attackType, riskScore: r.riskScore })),
      websiteScans: websiteScans.map(w => ({ timestamp: w.timestamp, domain: w.domain, securityScore: w.securityScore, riskScore: w.riskScore, threats: w.threats })),
    };

    if (format === 'json') {
      return new NextResponse(JSON.stringify(report, null, 2), {
        headers: { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename="ai-nms-report-${Date.now()}.json"` },
      });
    }

    const csvRows = [
      ['Timestamp', 'IP', 'Port', 'Protocol', 'Requests', 'Risk Score', 'Status', 'Attack Type'],
      ...traffic.map(t => [new Date(t.timestamp).toISOString(), t.ip, t.port, t.protocol, t.requestCount, t.riskScore ?? 0, t.threatStatus ?? 'Normal', t.attackType ?? 'None']),
    ];
    return new NextResponse(csvRows.map(r => r.join(',')).join('\n'), {
      headers: { 'Content-Type': 'text/csv', 'Content-Disposition': `attachment; filename="ai-nms-traffic-${Date.now()}.csv"` },
    });
  } catch (err) {
    return NextResponse.json({ success: false, message: 'Export failed' }, { status: 500 });
  }
}
