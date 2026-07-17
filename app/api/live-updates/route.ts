import { NextRequest } from 'next/server';
import store from '@/lib/sessionStore';
import { registerSSEClient } from '../sandbox-scan/route';

export const dynamic = 'force-dynamic';
// Vercel: increase function timeout for SSE (max 60s on hobby, 300s on pro)
export const maxDuration = 60;

export async function GET(req: NextRequest) {
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    start(controller) {
      const send = (data: string) => {
        try {
          controller.enqueue(encoder.encode(`data: ${data}\n\n`));
        } catch {}
      };

      // Send initial snapshot immediately
      send(JSON.stringify({
        traffic:      store.getTraffic(50),
        alerts:       store.getAlerts(50),
        recentSites:  store.getRecentSites(),
        blockedIPs:   store.getBlockedIPs(),
        responseLogs: store.getResponseLogs(20),
      }));

      // Register for future broadcasts
      const unregister = registerSSEClient(send);

      // Heartbeat every 15s to keep connection alive
      const heartbeat = setInterval(() => {
        try { controller.enqueue(encoder.encode(': ping\n\n')); } catch {}
      }, 15000);

      // Cleanup on disconnect
      req.signal.addEventListener('abort', () => {
        clearInterval(heartbeat);
        unregister();
        try { controller.close(); } catch {}
      });
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type':      'text/event-stream',
      'Cache-Control':     'no-cache, no-transform',
      'Connection':        'keep-alive',
      'X-Accel-Buffering': 'no',
    },
  });
}
