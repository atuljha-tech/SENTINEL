// ============================================================
// SENTINEL MULTI-AGENT LLM ORCHESTRATOR
// Replaces the if/else risk-scoring pipeline with genuine
// LLM-driven tool selection. Groq Llama-3.3-70B decides which
// security agents to invoke and in what order.
// ============================================================

import Groq from 'groq-sdk';
import { randomUUID } from 'crypto';

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

// ── Tool definitions exposed to the LLM ──────────────────────
const SENTINEL_TOOLS = [
  {
    name: 'threat_intel_lookup',
    description: 'Check IP or domain against known threat intelligence feeds. Returns severity and category.',
  },
  {
    name: 'sandbox_scan',
    description: 'Run URL through isolated Playwright browser. Returns riskScore, threats, cookies, scripts.',
  },
  {
    name: 'civic_log',
    description: 'Log a security event to the Civic governance audit trail with immutable record.',
  },
  {
    name: 'block_ip',
    description: 'Block an IP address at network level. Requires riskScore >= 80 or explicit threat.',
  },
  {
    name: 'rate_limit',
    description: 'Apply rate limiting to an IP. Use for medium-risk or bot traffic.',
  },
  {
    name: 'captcha_challenge',
    description: 'Issue CAPTCHA challenge. Use for brute force or bot traffic patterns.',
  },
  {
    name: 'alert_only',
    description: 'Log a human-reviewable alert without taking automated action.',
  },
] as const;

type SentinelTool = (typeof SENTINEL_TOOLS)[number]['name'];

export interface ToolCall {
  tool: SentinelTool;
  params: Record<string, unknown>;
  reason: string;
}

export interface OrchestratorDecision {
  sessionId: string;
  timestamp: string;
  threatContext: Record<string, unknown>;
  tool_calls: ToolCall[];
  reasoning: string;
  overallRisk: 'low' | 'medium' | 'high' | 'critical';
  requiresHumanReview: boolean;
  confidence: number;
}

// ── Build the orchestrator prompt ─────────────────────────────
function buildPrompt(context: Record<string, unknown>): string {
  return `You are SENTINEL's multi-agent security orchestrator. You coordinate specialized security agents to protect AI systems and users from cyber threats.

AVAILABLE AGENTS / TOOLS:
${SENTINEL_TOOLS.map(t => `- ${t.name}: ${t.description}`).join('\n')}

INCOMING THREAT CONTEXT:
${JSON.stringify(context, null, 2)}

RULES:
1. Always call civic_log for any threat with riskScore >= 35
2. Call sandbox_scan if a suspicious URL is present and not yet scanned
3. Only call block_ip if riskScore >= 80 OR if the IP is in known malicious lists
4. Call rate_limit for DDoS or brute force with riskScore 60-79
5. Call captcha_challenge for bot traffic or credential stuffing
6. If confidence < 75 and riskScore 60-80, set requiresHumanReview: true instead of auto-blocking
7. Never call more than 4 tools in one orchestration cycle

Respond with ONLY valid JSON in this exact structure:
{
  "reasoning": "Brief explanation of your decision (1-2 sentences)",
  "overallRisk": "low|medium|high|critical",
  "confidence": 0-100,
  "requiresHumanReview": true|false,
  "tool_calls": [
    {
      "tool": "tool_name",
      "params": { "key": "value" },
      "reason": "Why this tool is being called"
    }
  ]
}`;
}

// ── Main orchestration function ───────────────────────────────
export async function orchestrate(
  context: Record<string, unknown>
): Promise<OrchestratorDecision> {
  const sessionId = randomUUID();
  const timestamp = new Date().toISOString();

  // Fallback decision if LLM is unavailable
  const fallback = (): OrchestratorDecision => {
    const risk = (context.riskScore as number) ?? 0;
    const tool_calls: ToolCall[] = [];

    if (risk >= 80) {
      tool_calls.push({ tool: 'block_ip', params: { ip: context.ip, riskScore: risk }, reason: 'Critical risk — auto-block' });
      tool_calls.push({ tool: 'civic_log', params: { event: 'auto_block', ip: context.ip, riskScore: risk }, reason: 'Governance audit' });
    } else if (risk >= 60) {
      tool_calls.push({ tool: 'rate_limit', params: { ip: context.ip, riskScore: risk }, reason: 'High risk — rate limit' });
      tool_calls.push({ tool: 'civic_log', params: { event: 'rate_limit', ip: context.ip, riskScore: risk }, reason: 'Governance audit' });
    } else if (risk >= 35) {
      tool_calls.push({ tool: 'alert_only', params: { ip: context.ip, riskScore: risk }, reason: 'Medium risk — monitor' });
      tool_calls.push({ tool: 'civic_log', params: { event: 'alert', ip: context.ip, riskScore: risk }, reason: 'Governance audit' });
    }

    return {
      sessionId, timestamp, threatContext: context,
      tool_calls,
      reasoning: 'Rule-based fallback (LLM unavailable)',
      overallRisk: risk >= 80 ? 'critical' : risk >= 60 ? 'high' : risk >= 35 ? 'medium' : 'low',
      requiresHumanReview: false,
      confidence: 70,
    };
  };

  if (!process.env.GROQ_API_KEY) return fallback();

  try {
    const completion = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      temperature: 0.2,
      max_tokens: 1024,
      response_format: { type: 'json_object' },
      messages: [{ role: 'user', content: buildPrompt(context) }],
    });

    const raw = completion.choices[0]?.message?.content ?? '{}';
    const parsed = JSON.parse(raw);

    return {
      sessionId,
      timestamp,
      threatContext: context,
      tool_calls:          Array.isArray(parsed.tool_calls) ? parsed.tool_calls : [],
      reasoning:           parsed.reasoning ?? 'No reasoning provided',
      overallRisk:         parsed.overallRisk ?? 'low',
      requiresHumanReview: parsed.requiresHumanReview ?? false,
      confidence:          parsed.confidence ?? 80,
    };
  } catch (err) {
    console.error('[Orchestrator] LLM error — falling back:', err);
    return fallback();
  }
}

// ── Execute orchestrator tool_calls against real services ─────
export async function executeToolCalls(
  decision: OrchestratorDecision,
  services: {
    blockIP?: (ip: string, reason: string) => void;
    rateLimit?: (ip: string, reason: string) => void;
    civicLog?: (event: string, params: Record<string, unknown>) => Promise<void>;
    sandboxScan?: (url: string) => Promise<unknown>;
  }
): Promise<{ tool: string; result: 'executed' | 'skipped'; reason: string }[]> {
  const results: { tool: string; result: 'executed' | 'skipped'; reason: string }[] = [];

  for (const call of decision.tool_calls) {
    try {
      switch (call.tool) {
        case 'block_ip':
          if (services.blockIP && call.params.ip) {
            services.blockIP(String(call.params.ip), call.reason);
            results.push({ tool: call.tool, result: 'executed', reason: call.reason });
          } else {
            results.push({ tool: call.tool, result: 'skipped', reason: 'No blockIP service or IP' });
          }
          break;

        case 'rate_limit':
        case 'captcha_challenge':
          if (services.rateLimit && call.params.ip) {
            services.rateLimit(String(call.params.ip), call.reason);
            results.push({ tool: call.tool, result: 'executed', reason: call.reason });
          } else {
            results.push({ tool: call.tool, result: 'skipped', reason: 'No rateLimit service' });
          }
          break;

        case 'civic_log':
          if (services.civicLog) {
            await services.civicLog(String(call.params.event ?? 'security_event'), call.params);
            results.push({ tool: call.tool, result: 'executed', reason: call.reason });
          } else {
            results.push({ tool: call.tool, result: 'skipped', reason: 'No civic service' });
          }
          break;

        case 'sandbox_scan':
          if (services.sandboxScan && call.params.url) {
            await services.sandboxScan(String(call.params.url));
            results.push({ tool: call.tool, result: 'executed', reason: call.reason });
          } else {
            results.push({ tool: call.tool, result: 'skipped', reason: 'No sandbox service or URL' });
          }
          break;

        case 'alert_only':
        case 'threat_intel_lookup':
          results.push({ tool: call.tool, result: 'executed', reason: call.reason });
          break;

        default:
          results.push({ tool: call.tool, result: 'skipped', reason: 'Unknown tool' });
      }
    } catch (err) {
      results.push({ tool: call.tool, result: 'skipped', reason: `Error: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  return results;
}
