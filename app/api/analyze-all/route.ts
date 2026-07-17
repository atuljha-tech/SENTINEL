import { NextResponse } from 'next/server';
import store from '@/lib/sessionStore';
import { aiDetector } from '@/lib/ai-detection';
import Groq from 'groq-sdk';

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

export async function POST() {
  try {
    const unanalyzed = store.getUnanalyzed(20);
    const allTraffic = store.getTraffic(200) as any[];
    let analyzedCount = 0;

    for (const traffic of unanalyzed) {
      let riskScore = 0;
      let attackType = 'None';
      let reason = '';

      try {
        const prompt = `Analyze this network traffic for security threats:
IP: ${traffic.ip}
Port: ${traffic.port}
Protocol: ${traffic.protocol}
Request Count: ${traffic.requestCount}

Return ONLY valid JSON: { "riskScore": 0-100, "attackType": "DDoS/Brute Force/Port Scan/Bot Traffic/None", "reason": "brief explanation" }`;

        const completion = await groq.chat.completions.create({
          messages: [{ role: 'user', content: prompt }],
          model: 'llama-3.3-70b-versatile',
          temperature: 0.3,
          response_format: { type: 'json_object' },
        });

        const analysis = JSON.parse(completion.choices[0]?.message?.content ?? '{}');
        riskScore  = Math.round((Number(analysis.riskScore) || 0) * 10) / 10;
        attackType = analysis.attackType || 'None';
        reason     = analysis.reason     || '';
      } catch {
        // Fallback to local rule-based detector
        const result = aiDetector.detect(traffic as any, allTraffic);
        riskScore  = result.riskScore;
        attackType = result.attackType;
        reason     = result.reasons.join(', ');
      }

      const threatStatus = riskScore >= 70 ? 'Attack' : riskScore >= 35 ? 'Suspicious' : 'Normal';
      const alertFlag    = riskScore >= 35;

      store.updateTraffic(traffic.id, { riskScore, attackType, threatStatus, alertFlag, analyzedAt: new Date().toISOString(), aiReason: reason });

      if (alertFlag) {
        store.addDetection({
          trafficId:    traffic.id,
          ip:           traffic.ip,
          port:         traffic.port,
          protocol:     traffic.protocol,
          requestCount: traffic.requestCount,
          riskScore, threatStatus: threatStatus as any, attackType, alertFlag,
          reasons:      [reason || `${attackType} pattern detected`],
          recommendations: [],
        });
      }

      analyzedCount++;
    }

    return NextResponse.json({ success: true, analyzed: analyzedCount });
  } catch (err) {
    console.error('analyze-all error:', err);
    return NextResponse.json({ success: false, error: String(err) });
  }
}
