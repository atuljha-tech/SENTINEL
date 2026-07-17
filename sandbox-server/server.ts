/**
 * AI-NMS Sandbox Browser Server
 * Runs on port 4000 — separate from Next.js
 *
 * Architecture:
 *   Frontend (Next.js sandbox page)
 *     ↕ WebSocket (ws://)
 *   This server
 *     ↕ Playwright API
 *   Isolated Chromium context
 *
 * Protocol (JSON over WebSocket):
 *   Client → Server:
 *     { type: 'start',    url: string }
 *     { type: 'click',    x: number, y: number }
 *     { type: 'scroll',   x: number, y: number, deltaX: number, deltaY: number }
 *     { type: 'keydown',  key: string }
 *     { type: 'navigate', url: string }
 *     { type: 'back' }
 *     { type: 'forward' }
 *     { type: 'reload' }
 *
 *   Server → Client:
 *     { type: 'frame',   data: string (base64 PNG), url: string, title: string }
 *     { type: 'status',  message: string }
 *     { type: 'error',   message: string }
 *     { type: 'closed' }
 */

import express from 'express';
import http from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import cors from 'cors';
import { chromium, Browser, BrowserContext, Page } from 'playwright';

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// ── One session at a time ──
interface Session {
  browser: Browser;
  context: BrowserContext;
  page: Page;
  ws: WebSocket;
  frameInterval: ReturnType<typeof setInterval> | null;
  idleTimer: ReturnType<typeof setTimeout> | null;
  lastActivity: number;
}

let activeSession: Session | null = null;

async function closeSession() {
  if (!activeSession) return;
  const s = activeSession;
  activeSession = null;
  if (s.frameInterval) clearInterval(s.frameInterval);
  if (s.idleTimer)     clearTimeout(s.idleTimer);
  try { await s.page.close(); }    catch {}
  try { await s.context.close(); } catch {}
  try { await s.browser.close(); } catch {}
  console.log('[sandbox] session closed');
}

function resetIdle(session: Session) {
  session.lastActivity = Date.now();
  if (session.idleTimer) clearTimeout(session.idleTimer);
  // Auto-close after 3 minutes of inactivity
  session.idleTimer = setTimeout(() => {
    console.log('[sandbox] idle timeout — closing session');
    if (session.ws.readyState === WebSocket.OPEN) {
      session.ws.send(JSON.stringify({ type: 'status', message: 'Session closed due to inactivity' }));
    }
    closeSession();
  }, 3 * 60 * 1000);
}

async function startSession(ws: WebSocket, url: string) {
  // Close any existing session first
  await closeSession();

  ws.send(JSON.stringify({ type: 'status', message: 'Launching isolated Chromium...' }));

  const browser = await chromium.launch({
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
    ],
  });

  const context = await browser.newContext({
    viewport: { width: 1280, height: 720 },
    ignoreHTTPSErrors: true,
    // Security isolation
    permissions: [],
    acceptDownloads: false,
    // No persistent storage
    storageState: undefined,
  });

  // Block clipboard, downloads, file access
  await context.route('**/*', (route) => {
    const url = route.request().url();
    // Block file:// and data: URIs that could exfiltrate data
    if (url.startsWith('file://')) {
      route.abort();
      return;
    }
    route.continue();
  });

  const page = await context.newPage();

  const session: Session = {
    browser, context, page, ws,
    frameInterval: null,
    idleTimer: null,
    lastActivity: Date.now(),
  };
  activeSession = session;

  ws.send(JSON.stringify({ type: 'status', message: `Navigating to ${url}...` }));

  try {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });
  } catch (e) {
    ws.send(JSON.stringify({ type: 'status', message: 'Page loaded (some resources may have timed out)' }));
  }

  // Start screenshot streaming — 10 fps
  session.frameInterval = setInterval(async () => {
    if (!activeSession || activeSession.ws !== ws) return;
    if (ws.readyState !== WebSocket.OPEN) {
      clearInterval(session.frameInterval!);
      return;
    }
    try {
      const screenshot = await page.screenshot({ type: 'jpeg', quality: 70 });
      const currentUrl = page.url();
      const title = await page.title().catch(() => '');
      ws.send(JSON.stringify({
        type:  'frame',
        data:  screenshot.toString('base64'),
        url:   currentUrl,
        title,
      }));
    } catch {}
  }, 100); // 10 fps

  resetIdle(session);
}

// ── WebSocket handler ──
wss.on('connection', (ws) => {
  console.log('[sandbox] client connected');

  ws.on('message', async (raw) => {
    let msg: any;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    if (!activeSession || activeSession.ws !== ws) {
      if (msg.type === 'start' && msg.url) {
        await startSession(ws, msg.url);
      }
      return;
    }

    const { page } = activeSession;
    resetIdle(activeSession);

    try {
      switch (msg.type) {
        case 'start':
          await startSession(ws, msg.url);
          break;

        case 'click':
          await page.mouse.click(msg.x, msg.y);
          break;

        case 'scroll':
          await page.mouse.wheel(msg.deltaX ?? 0, msg.deltaY ?? 0);
          break;

        case 'keydown':
          await page.keyboard.press(msg.key);
          break;

        case 'type':
          await page.keyboard.type(msg.text ?? '');
          break;

        case 'navigate': {
          const dest = msg.url.startsWith('http') ? msg.url : `https://${msg.url}`;
          await page.goto(dest, { waitUntil: 'domcontentloaded', timeout: 15000 }).catch(() => {});
          break;
        }

        case 'back':
          await page.goBack({ waitUntil: 'domcontentloaded', timeout: 8000 }).catch(() => {});
          break;

        case 'forward':
          await page.goForward({ waitUntil: 'domcontentloaded', timeout: 8000 }).catch(() => {});
          break;

        case 'reload':
          await page.reload({ waitUntil: 'domcontentloaded', timeout: 8000 }).catch(() => {});
          break;
      }
    } catch (e) {
      ws.send(JSON.stringify({ type: 'error', message: String(e) }));
    }
  });

  ws.on('close', () => {
    console.log('[sandbox] client disconnected');
    // Don't close session immediately — allow reconnect within 10s
    setTimeout(() => {
      if (activeSession && activeSession.ws === ws) {
        closeSession();
      }
    }, 10000);
  });
});

// ── Health check ──
app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    session: activeSession ? 'active' : 'idle',
  });
});

// ── Start ──
const PORT = 4000;
server.listen(PORT, () => {
  console.log(`[sandbox] server running on ws://localhost:${PORT}`);
});
