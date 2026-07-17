// ============================================================
// SENTINEL GOVERNANCE REPORT GENERATOR
// POST /api/civic-audit/report
// Converts a Civic audit entry into a human-readable
// plain-English incident report via Groq Llama-3.3-70B.
// ============================================================

import { NextRequest, NextResponse } from 'next/server';
import store from '@/lib/sessionStore';
import Groq from 'groq-sdk';

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

async function generateReport(incident: {
  url?: string;
  ip?: string;
  threatType: string;
  riskScore: number;
  actions: string[];
  auditId: string;
}): Promise<string> {
  if (!process.env.GROQ_API_KEY) {
    return `WHAT HAPPENED: A ${incident.threatType} event was detected.\nTHREAT DETAILS:\n· Risk score: ${incident.riskScore}/100\nWHAT WAS DONE: ${incident.actions.join(', ')}\nGOVERNANCE RECORD: Audit ID ${incident.auditId}`;
  }

  const completion = await groq.chat.completions.create({
    model: 'llama-3.3-70b-versatile',
    temperature: 0.4,
    max_tokens: 400,
    messages: [{
      role: 'user',
      content: `Generate a plain-English security incident report for non-technical users.

Incident details:
- URL/IP: ${incident.url ?? incident.ip ?? 'Unknown'}
- Threat type: ${incident.threatType}
- Risk score: ${incident.riskScore}/100
- Actions taken: ${incident.actions.join(', ')}
- Audit ID: ${incident.auditId}

Format as:
WHAT HAPPENED: (1 sentence)
THREAT DETAILS: (2-3 bullet points)
WHAT WAS DONE: (1-2 sentences)
YOUR NEXT STEP: (1 sentence recommendation)
GOVERNANCE RECORD: Audit ID ${incident.auditId}`,
    }],
  });

  return completion.choices[0]?.message?.content?.trim() ?? 'Report generation failed';
}

export async function POST(req: NextRequest) {
  try {
    const { incidentId, auditId, ip, url, threatType, riskScore, actions } = await req.json();

    const logs  = store.getCivicLogs(200);
    const entry = logs.find(l => l.id === incidentId || l.civicCallId === auditId);

    const incident = {
      url:        url        ?? entry?.params?.url as string,
      ip:         ip         ?? entry?.params?.ip  as string,
      threatType: threatType ?? entry?.tool        ?? 'Unknown Threat',
      riskScore:  riskScore  ?? (entry?.params?.riskScore as number ?? 0),
      actions:    actions    ?? [entry?.result === 'allowed' ? 'Action executed' : 'Action blocked by guardrail'],
      auditId:    auditId    ?? incidentId ?? entry?.id ?? 'N/A',
    };

    const report = await generateReport(incident);

    return NextResponse.json({
      success:     true,
      report,
      incident,
      generatedAt: new Date().toISOString(),
      model:       'Groq Llama-3.3-70B',
    });
  } catch (err) {
    console.error('[Report] Error:', err);
    return NextResponse.json({ success: false, error: 'Report generation failed' }, { status: 500 });
  }
}

export async function GET() {
  const logs        = store.getCivicLogs(20);
  const highSeverity = logs.filter(l =>
    l.tool === 'block_ip' || l.tool === 'rate_limit_ip' || (l.params?.riskScore as number) >= 70
  ).slice(0, 5);

  return NextResponse.json({
    success:   true,
    incidents: highSeverity.map(l => ({
      id:        l.id,
      timestamp: l.timestamp,
      tool:      l.tool,
      ip:        l.params?.ip,
      riskScore: l.params?.riskScore,
      result:    l.result,
      auditId:   l.civicCallId ?? l.id,
    })),
  });
}
