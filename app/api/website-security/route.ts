import { NextRequest, NextResponse } from 'next/server';
import store from '@/lib/sessionStore';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { domain, securityScore, riskScore, threats, recommendations, summary, attackType, url } = body;

    const hasRealThreats = Array.isArray(threats) && threats.length > 0 &&
      !['No threats detected', 'No specific threats identified', 'Analysis complete'].includes(threats[0]);

    // Always save extension scans; only skip truly empty API calls
    const shouldSave = body.alwaysSave === true || hasRealThreats || (riskScore ?? 0) > 10;

    if (!shouldSave) {
      return NextResponse.json({ success: true, message: 'Skipped — no data', hasRealThreats: false });
    }

    store.addWebsiteScan({
      domain:        domain ?? 'unknown',
      url:           url    ?? '',
      securityScore: securityScore ?? 100,
      riskScore:     riskScore     ?? 0,
      threats:       threats       ?? [],
      recommendations: recommendations ?? [],
      summary:       summary       ?? '',
      attackType:    attackType    ?? 'none',
      severity:      (riskScore ?? 0) >= 70 ? 'critical' : (riskScore ?? 0) >= 50 ? 'high' : (riskScore ?? 0) >= 30 ? 'medium' : 'low',
      cookiesCount:  body.cookiesCount ?? 0,
      scriptsCount:  body.scriptsCount ?? 0,
    });

    return NextResponse.json({ success: true, message: 'Scan recorded', hasRealThreats });
  } catch (err) {
    console.error('website-security POST error:', err);
    return NextResponse.json({ success: false, message: 'Failed to record scan' }, { status: 500 });
  }
}

export async function GET() {
  try {
    const scans  = store.getWebsiteScans(30).map(s => ({ ...s, _id: s.id }));
    const alerts = store.getAlerts(20)
      .filter(a => a.type === 'website')
      .map(a => ({ ...a, _id: a.id }));
    const stats  = store.getWebsiteStats();

    return NextResponse.json({ success: true, scans, alerts, stats, count: scans.length, alertCount: alerts.length });
  } catch (err) {
    return NextResponse.json({ success: false, message: 'Failed to fetch security data' }, { status: 500 });
  }
}
