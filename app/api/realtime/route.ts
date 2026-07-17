import { NextResponse } from 'next/server';
import store from '@/lib/sessionStore';

export async function GET() {
  try {
    const traffic = store.getTraffic(20);
    const alerts  = store.getAlertDetections(10);
    const summary = store.getSummary();

    const highRisk   = traffic.filter(t => (t.riskScore ?? 0) >= 70).length;
    const threatLevel = highRisk > 10 ? 'critical' : highRisk > 5 ? 'high' : highRisk > 0 ? 'medium' : 'low';

    return NextResponse.json({
      success: true,
      stats: {
        packetsPerSecond: traffic.length / 10,
        alertsPerMinute:  alerts.length * 2,
        threatLevel,
        activeThreats:    alerts.length,
        topAttacker:      alerts[0]?.ip ?? null,
        ...summary,
      },
      recentTraffic: traffic.slice(0, 10),
      recentAlerts:  alerts.slice(0, 5),
      timestamp:     new Date(),
    });
  } catch {
    return NextResponse.json({ success: false, message: 'Failed to fetch real-time data' }, { status: 500 });
  }
}
