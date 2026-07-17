import { NextRequest, NextResponse } from 'next/server';
import { scanWebsiteInSandbox } from '@/lib/sandboxScanner';
import store from '@/lib/sessionStore';

export async function POST(req: NextRequest) {
  try {
    const { url } = await req.json();
    if (!url || typeof url !== 'string') {
      return NextResponse.json({ success: false, error: 'url required' }, { status: 400 });
    }

    const result = await scanWebsiteInSandbox(url);

    // Persist to sessionStore
    store.addWebsiteScan({
      domain:        result.domain,
      url:           result.url,
      securityScore: result.securityScore,
      riskScore:     result.riskScore,
      threats:       result.threats.map(t => t.text),
      recommendations: result.recommendations,
      summary:       `Sandbox scan: ${result.sandboxVerdict.toUpperCase()} — risk ${result.riskScore}`,
      attackType:    result.threats[0]?.level === 'critical' ? 'phishing' : 'none',
      severity:      result.severity,
      cookiesCount:  result.cookiesCount,
      scriptsCount:  result.scriptsCount,
    });

    store.addRecentSite({
      url:           result.url,
      domain:        result.domain,
      riskScore:     result.riskScore,
      securityScore: result.securityScore,
      threats:       result.threats.map(t => t.text),
      timestamp:     result.timestamp,
      sandboxVerdict: result.sandboxVerdict,
    });

    // Broadcast SSE update
    broadcastUpdate();

    return NextResponse.json({ success: true, result });
  } catch (err) {
    console.error('sandbox-scan error:', err);
    return NextResponse.json({ success: false, error: 'Scan failed' }, { status: 500 });
  }
}

export async function GET() {
  return NextResponse.json({ success: true, recentSites: store.getRecentSites() });
}

// ── SSE broadcast helper (imported by live-updates) ──
let sseClients: Set<(data: string) => void> = new Set();

export function registerSSEClient(send: (data: string) => void) {
  sseClients.add(send);
  return () => sseClients.delete(send);
}

export function broadcastUpdate() {
  const payload = JSON.stringify({
    traffic:     store.getTraffic(50),
    alerts:      store.getAlerts(50),
    recentSites: store.getRecentSites(),
    blockedIPs:  store.getBlockedIPs(),
    responseLogs: store.getResponseLogs(20),
  });
  sseClients.forEach(send => { try { send(payload); } catch {} });
}
