import { NextResponse } from 'next/server';
import store from '@/lib/sessionStore';

export async function GET() {
  const summary = store.getSummary();
  return NextResponse.json({
    status:    'ok',
    service:   'SENTINEL',
    version:   '2.0.0',
    timestamp: new Date().toISOString(),
    uptime:    process.uptime(),
    groq:  !!process.env.GROQ_API_KEY,
    civic: !!process.env.CIVIC_API_KEY,
    store:     summary,
    endpoints: {
      clearance: '/api/v1/agent/clearance',
      forecast:  '/api/threat-forecast',
      registry:  '/api/registry',
      usage:     '/api/usage',
    },
  });
}
