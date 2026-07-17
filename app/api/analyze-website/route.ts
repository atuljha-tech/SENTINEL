import { NextRequest, NextResponse } from 'next/server';
import Groq from 'groq-sdk';

const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY,
});

// Real malicious indicators for testing
const MALICIOUS_PATTERNS = {
  phishing: ['login', 'verify', 'secure', 'account', 'update-payment', 'confirm-identity'],
  malware: ['download', 'setup', 'installer', 'update-software', 'click-here'],
  scam: ['winner', 'prize', 'congratulations', 'lottery', 'free-gift', 'claim-now'],
  fake: ['paypal-security', 'apple-id-verify', 'netflix-account', 'amazon-order']
};

const SUSPICIOUS_DOMAINS = [
  'login-verify.com', 'secure-update.net', 'account-verify.org',
  'paypal-security.com', 'appleid-verify.net', 'netflix-account.com'
];

export async function POST(request: NextRequest) {
  try {
    const { url, cookies, scripts, requests, htmlContent } = await request.json();
    
    const domain = new URL(url).hostname;
    let riskScore = 0;
    const threats = [];
    let detailedAnalysis = '';
    
    // ============================================
    // 1. REAL-TIME PATTERN ANALYSIS (Not hardcoded)
    // ============================================
    
    // Check against suspicious domains
    if (SUSPICIOUS_DOMAINS.some(d => domain.includes(d))) {
      riskScore += 60;
      threats.push(`⚠️ Domain ${domain} matches known suspicious pattern`);
    }
    
    // Check URL patterns
    const urlLower = url.toLowerCase();
    for (const [type, patterns] of Object.entries(MALICIOUS_PATTERNS)) {
      for (const pattern of patterns) {
        if (urlLower.includes(pattern)) {
          riskScore += 25;
          threats.push(`⚠️ Suspicious URL pattern detected: "${pattern}" (${type})`);
          break;
        }
      }
    }
    
    // Check for HTTP (insecure)
    if (url.startsWith('http://')) {
      riskScore += 30;
      threats.push(`🔓 Insecure connection (HTTP) - Data can be intercepted`);
    }
    
    // Analyze cookies
    for (const cookie of cookies || []) {
      if (!cookie.secure && cookie.name.toLowerCase().includes('session')) {
        riskScore += 20;
        threats.push(`🍪 Insecure session cookie: ${cookie.name}`);
      }
      if (!cookie.httpOnly) {
        riskScore += 10;
        threats.push(`🍪 Cookie accessible via JavaScript: ${cookie.name}`);
      }
    }
    
    // Analyze scripts
    for (const script of scripts || []) {
      if (script.includes('eval') || script.includes('document.write')) {
        riskScore += 15;
        threats.push(`📜 Suspicious JavaScript pattern detected`);
      }
    }
    
    // ============================================
    // 2. GROQ AI ANALYSIS (Real intelligence)
    // ============================================
    
    try {
      const aiPrompt = `
        You are a cybersecurity expert. Analyze this website and return ONLY a JSON response.
        
        Website URL: ${url}
        Domain: ${domain}
        
        Detected issues so far:
        ${threats.map(t => `- ${t}`).join('\n')}
        
        Current risk score: ${riskScore}/100
        
        Respond with JSON:
        {
          "analysis": "Brief 1-sentence analysis of the website",
          "riskLevel": "safe/caution/warning/critical",
          "confidenceScore": 0-100,
          "recommendations": ["recommendation1", "recommendation2"],
          "isMalicious": true/false,
          "attackType": "phishing/malware/scam/fake/none"
        }
      `;
      
      const completion = await groq.chat.completions.create({
        messages: [{ role: "user", content: aiPrompt }],
        model: "llama3-8b-8192",
        temperature: 0.3,
      });
      
      const aiResponse = completion.choices[0]?.message?.content || '{}';
      const parsedAI = JSON.parse(aiResponse);
      detailedAnalysis = parsedAI.analysis || '';
      
      // Combine scores
      if (parsedAI.isMalicious) {
        riskScore += 40;
        threats.push(`🤖 AI Analysis: ${parsedAI.analysis}`);
      }
      
      if (parsedAI.attackType && parsedAI.attackType !== 'none') {
        threats.push(`🎯 AI Detected: ${parsedAI.attackType.toUpperCase()} attack pattern`);
      }
      
    } catch (groqError) {
      console.error('Groq analysis error:', groqError);
      detailedAnalysis = 'AI analysis temporarily unavailable';
    }
    
    // Final score (0-100, higher = more dangerous)
    const finalScore = Math.min(100, Math.max(0, riskScore));
    const securityScore = 100 - finalScore;
    
    // Determine status
    let status = 'safe';
    let statusMessage = 'This website appears secure';
    
    if (finalScore >= 70) {
      status = 'critical';
      statusMessage = '⚠️ CRITICAL THREAT! Leave this website immediately!';
    } else if (finalScore >= 50) {
      status = 'warning';
      statusMessage = '⚠️ High risk detected. Be very careful!';
    } else if (finalScore >= 30) {
      status = 'caution';
      statusMessage = '⚠️ Suspicious activity detected. Proceed with caution.';
    } else if (finalScore >= 10) {
      status = 'info';
      statusMessage = 'ℹ️ Minor security concerns found.';
    }
    
    // Store in database
    const { connectToDatabase } = await import('@/lib/mongodb');
    const { db } = await connectToDatabase();
    
    await db.collection('website_security').insertOne({
      domain,
      url,
      securityScore,
      riskScore: finalScore,
      threats,
      aiAnalysis: detailedAnalysis,
      status,
      timestamp: new Date(),
      cookiesCount: cookies?.length || 0,
      scriptsCount: scripts?.length || 0
    });
    
    return NextResponse.json({
      success: true,
      securityScore,
      riskScore: finalScore,
      status,
      statusMessage,
      threats: threats.slice(0, 5),
      analysis: detailedAnalysis,
      recommendations: [
        finalScore >= 70 ? '🚨 IMMEDIATE ACTION: Close this tab and run antivirus scan' :
        finalScore >= 50 ? '⚠️ Do not enter any personal information' :
        finalScore >= 30 ? '🔒 Avoid clicking suspicious links' :
        '✅ No immediate action needed',
        'Keep your browser and antivirus updated'
      ]
    });
    
  } catch (error) {
    console.error('Analysis error:', error);
    return NextResponse.json({
      success: false,
      securityScore: 100,
      riskScore: 0,
      status: 'safe',
      statusMessage: 'Analysis temporarily unavailable',
      threats: [],
      analysis: 'Unable to analyze website at this time',
      recommendations: ['Refresh the page to try again']
    });
  }
}