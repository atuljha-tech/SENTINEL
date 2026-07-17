import { NextRequest, NextResponse } from 'next/server';
import Groq from 'groq-sdk';
import store from '@/lib/sessionStore';

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

export async function POST(request: NextRequest) {
  try {
    const { url, domain, htmlSnippet, cookies, scripts, forms } = await request.json();

    const prompt = `You are a cybersecurity expert. Analyze this website and return ONLY valid JSON.

Website URL: ${url}
Domain: ${domain}

PAGE ANALYSIS:
${htmlSnippet ? `HTML Snippet: ${htmlSnippet.substring(0, 2000)}` : 'No HTML available'}

COOKIES (${cookies?.length ?? 0} found):
${cookies?.slice(0, 10).map((c: any) => `- ${c.name}: secure=${c.secure}, httpOnly=${c.httpOnly}, sameSite=${c.sameSite}`).join('\n') || 'No cookies'}

SCRIPTS (${scripts?.length ?? 0} found):
${scripts?.slice(0, 5).join('\n') || 'No scripts'}

FORMS (${forms?.length ?? 0} found):
${forms?.slice(0, 5).map((f: any) => `- Action: ${f.action}, Method: ${f.method}`).join('\n') || 'No forms'}

Analyze for: phishing, security misconfigurations, malware, privacy issues.

Respond with JSON:
{
  "riskScore": 0-100,
  "securityScore": 0-100,
  "threats": ["threat1", "threat2"],
  "recommendations": ["rec1", "rec2"],
  "summary": "Brief 1-sentence analysis",
  "attackType": "phishing/malware/tracker/none",
  "severity": "critical/high/medium/low/safe"
}`;

    const completion = await groq.chat.completions.create({
      messages: [{ role: 'user', content: prompt }],
      model: 'llama-3.3-70b-versatile',
      temperature: 0.3,
      response_format: { type: 'json_object' },
    });

    const ai = JSON.parse(completion.choices[0]?.message?.content ?? '{}');

    // Store in session
    store.addWebsiteScan({
      domain:        domain ?? 'unknown',
      url:           url    ?? '',
      securityScore: ai.securityScore ?? 100,
      riskScore:     ai.riskScore     ?? 0,
      threats:       ai.threats       ?? [],
      recommendations: ai.recommendations ?? [],
      summary:       ai.summary       ?? '',
      attackType:    ai.attackType    ?? 'none',
      severity:      ai.severity      ?? 'safe',
      cookiesCount:  cookies?.length  ?? 0,
      scriptsCount:  scripts?.length  ?? 0,
    });

    return NextResponse.json({ success: true, ...ai });
  } catch (err) {
    console.error('groq-analyze error:', err);
    return NextResponse.json({
      success: false, riskScore: 0, securityScore: 100,
      threats: ['AI analysis temporarily unavailable'],
      recommendations: ['Refresh and try again'],
      summary: 'Analysis failed', attackType: 'unknown', severity: 'safe',
    });
  }
}
