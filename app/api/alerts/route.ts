import { NextResponse } from 'next/server';
import store from '@/lib/sessionStore';

export async function GET() {
  try {
    const alerts = store.getAlerts(50).map(a => ({ ...a, _id: a.id }));
    return NextResponse.json({ success: true, alerts, count: alerts.length });
  } catch {
    return NextResponse.json({ success: false, message: 'Failed to fetch alerts' }, { status: 500 });
  }
}
