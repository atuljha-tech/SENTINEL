import { NextResponse } from 'next/server';
import store from '@/lib/sessionStore';

function round1(n: number) { return Math.round(n * 10) / 10; }

export async function GET() {
  try {
    const rawAlerts = store.getAlertDetections(50);

    const alerts = rawAlerts.map(d => ({
      _id: d.id,
      threatStatus: d.threatStatus,
      attackType:   d.attackType,
      riskScore:    round1(d.riskScore),
      analyzedAt:   d.timestamp,
      alertFlag:    d.alertFlag,
      reasons:      d.reasons,
      trafficData: {
        ip:           d.ip,
        port:         d.port,
        protocol:     d.protocol,
        requestCount: d.requestCount,
      },
    }));

    const stats = store.getDetectionStats();

    return NextResponse.json({
      success:    true,
      alerts,
      detections: alerts,
      stats,
      count:      alerts.length,
      alertCount: alerts.length,
    });
  } catch (err) {
    console.error('Detect GET error:', err);
    return NextResponse.json({ success: false, message: 'Failed to fetch detections' }, { status: 500 });
  }
}
