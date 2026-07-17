// ============================================================
// SENTINEL AGENT CLEARANCE API — The ASP Core Endpoint
// Any external OKX.AI agent calls this before navigating
// to a URL. Returns: clearanceGranted, riskScore, auditId.
//
// POST /api/v1/agent/clearance
// {
//   "agentId": "my-trading-bot",
//   "url": "https://suspicious-defi.xyz",
//   "context": "about to approve a token swap",
//   "agentKey": "sk-sentinel-xxxx"       ← optional on free tier
// }
// ============================================================

import { NextRequest, NextResponse } from 'next/server';
import { scanWebsiteInSandbox } from '@/lib/sandboxScanner';
import civicHub from '@/lib/civicClient';
import { orchestrate } from '@/lib/orchestrator';
import threatRegistry from '@/lib/threatRegistry';
import usageTracker from '@/lib/usageTracker';
import store from '@/lib/sessionStore';
import { randomUUID } from 'crypto';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Agent-Key',
};

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: CORS_HEADERS });
}

export async function POST(req: NextRequest) {
  const requestStart = Date.now();

  try {
    const body = await req.json();
    const {
      agentId  = 'anonymous',
      url,
      context  = '',
      agentKey = req.headers.get('x-agent-key') ?? 'sk-sentinel-demo0000',
    } = body;

    if (!url || typeof url !== 'string') {
      return NextResponse.json(
        { error: 'url is required', code: 'MISSING_URL' },
        { status: 400, headers: CORS_HEADERS }
      );
    }

    // ── Rate limit / tier check ──────────────────────────────
    const limitCheck = usageTracker.checkLimit(agentKey);
    if (!limitCheck.allowed) {
      return NextResponse.json(
        {
          clearanceGranted: false,
          riskScore:        0,
          reason:           limitCheck.reason,
          suggestedAction:  'UPGRADE',
          auditId:          randomUUID(),
          humanReviewUrl:   `${process.env.NEXT_PUBLIC_BASE_URL ?? ''}/upgrade`,
          code:             'RATE_LIMITED',
        },
        { status: 429, headers: CORS_HEADERS }
      );
    }

    const keyData = usageTracker.validateKey(agentKey);
    const tier    = keyData?.tier ?? 'free';

    // ── 1. Quick registry check (instant) ───────────────────
    let domain = '';
    try { domain = new URL(url).hostname; } catch { domain = url; }

    const registryHit = threatRegistry.check(url);

    // ── 2. Sandbox scan ─────────────────────────────────────
    let sandboxResult;
    try {
      sandboxResult = await scanWebsiteInSandbox(url);
    } catch {
      sandboxResult = null;
    }

    const riskScore = sandboxResult?.riskScore ?? (registryHit?.riskScore ?? 0);

    // ── 3. LLM Orchestrator decision ─────────────────────────
    const orchestratorCtx = {
      agentId,
      url,
      domain,
      context,
      riskScore,
      registryHit:   registryHit ? { category: registryHit.category, riskScore: registryHit.riskScore } : null,
      threats:       sandboxResult?.threats?.map(t => t.text) ?? [],
      scriptsCount:  sandboxResult?.scriptsCount ?? 0,
      cookiesCount:  sandboxResult?.cookiesCount ?? 0,
      sandboxVerdict: sandboxResult?.sandboxVerdict ?? 'safe',
    };

    const decision = await orchestrate(orchestratorCtx);

    // ── 4. Civic governance log ──────────────────────────────
    const civicResult = await civicHub.executeTool('log_security_event', {
      event:       'agent_clearance_request',
      agentId,
      url,
      riskScore,
      decision:    decision.overallRisk,
      confidence:  decision.confidence,
      source:      'agent-clearance-api',
    });

    // ── 5. Build clearance response ──────────────────────────
    const clearanceGranted =
      decision.overallRisk === 'low' ||
      (decision.overallRisk === 'medium' && decision.confidence < 70);

    const suggestedAction: string =
      decision.overallRisk === 'critical' ? 'ABORT' :
      decision.overallRisk === 'high'     ? 'ABORT' :
      decision.overallRisk === 'medium'   ? 'PROCEED_WITH_CAUTION' :
      'PROCEED';

    const reason =
      registryHit
        ? `Known threat in registry: ${registryHit.description}`
        : sandboxResult && sandboxResult.threats.length > 0
          ? sandboxResult.threats[0].text
          : decision.reasoning;

    const humanReviewUrl = `${process.env.NEXT_PUBLIC_BASE_URL ?? 'https://sentinel.vercel.app'}/review/${civicResult.auditId}`;

    // ── 6. Persist to store ──────────────────────────────────
    store.addWebsiteScan({
      domain,
      url,
      securityScore: sandboxResult?.securityScore ?? (100 - riskScore),
      riskScore,
      threats:       sandboxResult?.threats?.map(t => t.text) ?? [],
      recommendations: sandboxResult?.recommendations ?? [decision.reasoning],
      summary:       `Agent clearance: ${clearanceGranted ? 'GRANTED' : 'DENIED'} — ${reason}`,
      attackType:    decision.overallRisk === 'critical' ? 'phishing' : 'none',
      severity:      decision.overallRisk,
      cookiesCount:  sandboxResult?.cookiesCount ?? 0,
      scriptsCount:  sandboxResult?.scriptsCount ?? 0,
    });

    // ── 7. Track usage ────────────────────────────────────────
    usageTracker.record({
      agentKey,
      agentId,
      tool:          'agent_clearance',
      tier,
      billableUnits: 1,
      latencyMs:     Date.now() - requestStart,
      success:       true,
    });

    return NextResponse.json(
      {
        clearanceGranted,
        riskScore,
        reason,
        suggestedAction,
        overallRisk:         decision.overallRisk,
        confidence:          decision.confidence,
        requiresHumanReview: decision.requiresHumanReview,
        auditId:             civicResult.auditId,
        humanReviewUrl,
        threats:             sandboxResult?.threats?.slice(0, 3).map(t => t.text) ?? [],
        orchestratorDecision: {
          reasoning:  decision.reasoning,
          tool_calls: decision.tool_calls.map(tc => tc.tool),
        },
        meta: {
          tier,
          scansRemaining: limitCheck.remaining - 1,
          latencyMs:      Date.now() - requestStart,
          sandboxUsed:    !!sandboxResult,
          registryHit:    !!registryHit,
        },
      },
      { status: 200, headers: CORS_HEADERS }
    );
  } catch (err) {
    console.error('[Clearance API] Error:', err);
    return NextResponse.json(
      {
        clearanceGranted:  false,
        riskScore:         0,
        reason:            'Internal analysis error — treating as unverified',
        suggestedAction:   'PROCEED_WITH_CAUTION',
        auditId:           randomUUID(),
        error:             err instanceof Error ? err.message : 'Unknown error',
      },
      { status: 500, headers: CORS_HEADERS }
    );
  }
}
