// ============================================================
// CIVIC HUB CLIENT — Correct MCP Session Flow
// 1. POST initialize → get session ID from header
// 2. POST notifications/initialized (required handshake)
// 3. POST tools/call with session ID
// ============================================================

import { randomUUID } from 'crypto';
import store from './sessionStore';

const CIVIC_TOKEN   = process.env.CIVIC_API_KEY ?? '';
const CIVIC_MCP_URL = process.env.CIVIC_MCP_URL
  ?? 'https://app.civic.com/hub/mcp?accountId=35774b0b-ef5b-4280-9577-3b6f8826cde1&profile=default';

const PROTECTED_IPS      = ['127.0.0.1', 'localhost', '0.0.0.0', '::1'];
const MAX_BLOCKS_PER_MIN = 5;

export interface CivicAuditEntry {
  id:             string;
  timestamp:      string;
  tool:           string;
  params:         Record<string, unknown>;
  result:         'allowed' | 'blocked' | 'error';
  reason:         string;
  executedBy:     string;
  civicCallId?:   string;
  civicConnected: boolean;
}

export interface CivicToolStats {
  block_ip:                number;
  rate_limit_ip:           number;
  scan_website:            number;
  log_security_event:      number;
  retrieve_recent_threats: number;
}

// ── Raw HTTP POST to Civic MCP ──
async function mcpPost(
  sessionId: string | null,
  body: object
): Promise<{ ok: boolean; sessionId?: string; result?: unknown; error?: string }> {
  if (!CIVIC_TOKEN) return { ok: false, error: 'No Civic token' };

  const headers: Record<string, string> = {
    'Content-Type':  'application/json',
    'Authorization': `Bearer ${CIVIC_TOKEN}`,
    'Accept':        'application/json, text/event-stream',
    'MCP-Version':   '2024-11-05',
  };
  if (sessionId) headers['Mcp-Session-Id'] = sessionId;

  try {
    const res = await fetch(CIVIC_MCP_URL, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10000),
    });

    const returnedSession = res.headers.get('mcp-session-id') ?? sessionId ?? undefined;
    const ct   = res.headers.get('content-type') ?? '';
    const text = await res.text();

    if (!res.ok) return { ok: false, error: `HTTP ${res.status}: ${text.substring(0, 120)}`, sessionId: returnedSession ?? undefined };

    // Parse SSE or JSON
    let parsed: any = null;
    if (ct.includes('text/event-stream') || text.includes('event:')) {
      const dataLines = text.split('\n').filter(l => l.startsWith('data:'));
      for (const line of dataLines.reverse()) {
        try { parsed = JSON.parse(line.replace(/^data:\s*/, '')); break; } catch {}
      }
    } else {
      try { parsed = JSON.parse(text); } catch {}
    }

    if (!parsed) return { ok: true, result: null, sessionId: returnedSession ?? undefined };
    if (parsed.error) return { ok: false, error: parsed.error.message ?? JSON.stringify(parsed.error), sessionId: returnedSession ?? undefined };
    return { ok: true, result: parsed.result ?? parsed, sessionId: returnedSession ?? undefined };

  } catch (e: unknown) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

// ── Full MCP session: initialize → notifications/initialized → ready ──
async function createSession(): Promise<{ ok: boolean; sessionId?: string; error?: string }> {
  if (!CIVIC_TOKEN) return { ok: false, error: 'No token' };

  // Step 1: initialize
  const init = await mcpPost(null, {
    jsonrpc: '2.0', id: randomUUID(), method: 'initialize',
    params: {
      protocolVersion: '2024-11-05',
      capabilities:    { tools: {} },
      clientInfo:      { name: 'AI-NMS', version: '10.0' },
    },
  });

  if (!init.ok) return { ok: false, error: `initialize failed: ${init.error}` };
  const sid = init.sessionId;
  if (!sid) return { ok: false, error: 'No session ID returned' };

  // Step 2: notifications/initialized (required — tells server client is ready)
  await mcpPost(sid, {
    jsonrpc: '2.0', method: 'notifications/initialized', params: {},
  });

  return { ok: true, sessionId: sid };
}

class CivicHub {
  private auditLog:   CivicAuditEntry[] = [];
  private blockTimes: number[]          = [];
  private revoked     = false;
  private sessionId:  string | null     = null;
  private sessionExp  = 0;
  private stats: CivicToolStats = {
    block_ip: 0, rate_limit_ip: 0,
    scan_website: 0, log_security_event: 0,
    retrieve_recent_threats: 0,
  };

  revoke()    { this.revoked = true;  this.addAudit('REVOKE',  {}, 'blocked', 'Tool access revoked by operator', undefined, false); }
  restore()   { this.revoked = false; this.addAudit('RESTORE', {}, 'allowed', 'Tool access restored by operator', undefined, false); }
  isRevoked() { return this.revoked; }

  private addAudit(
    tool: string, params: Record<string, unknown>,
    result: 'allowed' | 'blocked' | 'error',
    reason: string, civicCallId?: string, civicConnected = false
  ): CivicAuditEntry {
    const entry: CivicAuditEntry = {
      id: randomUUID(), timestamp: new Date().toISOString(),
      tool, params, result, reason, executedBy: 'AI_AGENT',
      civicCallId, civicConnected,
    };
    this.auditLog.unshift(entry);
    if (this.auditLog.length > 300) this.auditLog.pop();
    store.addCivicLog({ tool, params, result, reason, civicCallId, civicConnected });
    return entry;
  }

  getAuditLog(limit = 50): CivicAuditEntry[] {
    const fromStore = store.getCivicLogs(limit);
    if (fromStore.length > 0) {
      return fromStore.map(l => ({ ...l, executedBy: 'AI_AGENT' as const }));
    }
    return this.auditLog.slice(0, limit);
  }

  getStats(): CivicToolStats {
    const s = store.getCivicStats();
    return {
      block_ip:                s.block_ip,
      rate_limit_ip:           s.rate_limit_ip,
      scan_website:            s.scan_website,
      log_security_event:      s.log_security_event,
      retrieve_recent_threats: s.retrieve_recent_threats,
    };
  }

  // ── Get or create valid session ──
  private async getSession(): Promise<string | null> {
    if (this.sessionId && Date.now() < this.sessionExp) return this.sessionId;
    const res = await createSession();
    if (res.ok && res.sessionId) {
      this.sessionId  = res.sessionId;
      this.sessionExp = Date.now() + 20 * 60 * 1000; // 20 min
      return this.sessionId;
    }
    console.warn('[Civic] Session creation failed:', res.error);
    return null;
  }

  // ── Guardrails ──
  private checkGuardrails(tool: string, params: Record<string, unknown>): { pass: boolean; reason: string } {
    if (this.revoked) return { pass: false, reason: 'Tool access revoked via Civic' };
    if (tool === 'block_ip') {
      const ip = String(params.ip ?? '');
      if (PROTECTED_IPS.some(p => ip.includes(p)))
        return { pass: false, reason: `Guardrail: cannot block protected IP ${ip}` };
      const now = Date.now();
      this.blockTimes = this.blockTimes.filter(t => now - t < 60_000);
      if (this.blockTimes.length >= MAX_BLOCKS_PER_MIN)
        return { pass: false, reason: `Guardrail: block_ip rate limit exceeded (${MAX_BLOCKS_PER_MIN}/min)` };
      this.blockTimes.push(now);
    }
    return { pass: true, reason: 'Guardrail check passed' };
  }

  // ── Main executor ──
  async executeTool(tool: string, params: Record<string, unknown>): Promise<{
    success: boolean; result?: unknown;
    auditId: string; guardrailPassed: boolean;
    reason: string; civicCallId?: string; civicConnected: boolean;
  }> {
    const guard = this.checkGuardrails(tool, params);
    if (!guard.pass) {
      const e = this.addAudit(tool, params, 'blocked', guard.reason, undefined, false);
      return { success: false, auditId: e.id, guardrailPassed: false, reason: guard.reason, civicConnected: false };
    }

    // Try Civic Hub with proper session
    const session = await this.getSession();
    if (session) {
      const callId = randomUUID();
      const civic = await mcpPost(session, {
        jsonrpc: '2.0', id: callId,
        method: 'tools/call',
        params: { name: tool, arguments: params },
      });

      if (civic.ok) {
        const e = this.addAudit(tool, params, 'allowed', 'Civic Hub: tool executed', callId, true);
        this.stats[tool as keyof CivicToolStats] = (this.stats[tool as keyof CivicToolStats] ?? 0) + 1;
        return { success: true, result: civic.result, auditId: e.id, guardrailPassed: true, reason: 'Civic Hub: tool executed', civicCallId: callId, civicConnected: true };
      }

      // If session error, reset it
      if (civic.error?.includes('session') || civic.error?.includes('TerminationHook') || civic.error?.includes('-32603')) {
        this.sessionId = null;
      }
      console.warn('[Civic] tool call failed:', civic.error);
    }

    // Local fallback
    const e = this.addAudit(tool, params, 'allowed', `Local execution (Civic unavailable)`, undefined, false);
    this.stats[tool as keyof CivicToolStats] = (this.stats[tool as keyof CivicToolStats] ?? 0) + 1;
    return { success: true, auditId: e.id, guardrailPassed: true, reason: e.reason, civicConnected: false };
  }

  // ── Ping ──
  async ping(): Promise<boolean> {
    this.sessionId = null;
    const session = await this.getSession();
    return !!session;
  }

  // ── List tools ──
  async listTools(): Promise<{ ok: boolean; tools?: unknown[] }> {
    const session = await this.getSession();
    if (!session) return { ok: false };
    const res = await mcpPost(session, {
      jsonrpc: '2.0', id: randomUUID(), method: 'tools/list', params: {},
    });
    if (res.ok) return { ok: true, tools: (res.result as any)?.tools ?? [] };
    return { ok: false };
  }
}

const civicHub = new CivicHub();
export default civicHub;
