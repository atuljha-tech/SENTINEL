// Sandbox Website Scanner — uses Playwright headless browser
// Collects real security signals before the user loads a site
// Uses identical scoring logic to the Chrome extension's realScore()

export interface SandboxResult {
  url: string;
  domain: string;
  scripts: string[];
  cookies: SandboxCookie[];
  scriptsCount: number;
  cookiesCount: number;
  mixedContent: number;
  suspiciousPatterns: string[];
  sandboxRiskScore: number;
  riskScore: number;
  securityScore: number;
  threats: SandboxThreat[];
  severity: 'safe' | 'warning' | 'high' | 'critical';
  recommendations: string[];
  sandboxVerdict: 'safe' | 'warning' | 'block';
  timestamp: string;
}

export interface SandboxCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string;
}

export interface SandboxThreat {
  level: 'low' | 'medium' | 'high' | 'critical';
  text: string;
}

const PHISH_PATTERNS = [
  { p: 'paypal', exclude: 'paypal.com' },
  { p: 'apple-id', exclude: 'apple.com' },
  { p: 'netflix-', exclude: 'netflix.com' },
  { p: 'login-verify', exclude: '' },
  { p: 'secure-update', exclude: '' },
  { p: 'account-confirm', exclude: '' },
  { p: 'verify-identity', exclude: '' },
];

const MALICIOUS_DOMAINS = [
  'malware-tracker.com', 'phishing-site.net', 'fake-login.org',
  'login-verify.com', 'secure-update.net', 'account-verify.org',
];

const SUSPICIOUS_JS = [
  'eval(', 'document.write(', 'atob(', 'fromCharCode', 'unescape(',
  'innerHTML =', 'outerHTML =', 'insertAdjacentHTML',
];

function extractDomain(url: string): string {
  try { return new URL(url).hostname; } catch { return url; }
}

function severityFromRisk(risk: number): SandboxResult['severity'] {
  if (risk >= 80) return 'critical';
  if (risk >= 60) return 'high';
  if (risk >= 35) return 'warning';
  return 'safe';
}

function verdictFromRisk(risk: number): SandboxResult['sandboxVerdict'] {
  if (risk >= 60) return 'block';
  if (risk >= 35) return 'warning';
  return 'safe';
}

// Lightweight fallback scanner (no browser) — used when Playwright unavailable
function lightweightScan(url: string): SandboxResult {
  const domain = extractDomain(url);
  const urlL = url.toLowerCase();
  let risk = 0;
  const threats: SandboxThreat[] = [];

  if (!url.startsWith('https://')) {
    risk += 40;
    threats.push({ level: 'critical', text: 'No HTTPS — data sent in plain text' });
  }

  for (const { p, exclude } of PHISH_PATTERNS) {
    if (urlL.includes(p) && (!exclude || !urlL.includes(exclude))) {
      risk += 45;
      threats.push({ level: 'critical', text: `Phishing URL pattern: "${p}"` });
      break;
    }
  }

  if (MALICIOUS_DOMAINS.some(d => domain.includes(d))) {
    risk += 60;
    threats.push({ level: 'critical', text: `Domain matches known malicious list: ${domain}` });
  }

  risk = Math.min(100, risk);
  const securityScore = Math.max(0, 100 - risk);

  return {
    url, domain,
    scripts: [], cookies: [],
    scriptsCount: 0, cookiesCount: 0,
    mixedContent: 0, suspiciousPatterns: [],
    sandboxRiskScore: risk,
    riskScore: risk,
    securityScore,
    threats,
    severity: severityFromRisk(risk),
    recommendations: risk > 0 ? ['Avoid this site', 'Check URL carefully'] : ['Site appears safe'],
    sandboxVerdict: verdictFromRisk(risk),
    timestamp: new Date().toISOString(),
  };
}

export async function scanWebsiteInSandbox(url: string): Promise<SandboxResult> {
  const domain = extractDomain(url);

  // Skip internal/localhost URLs
  if (!url.startsWith('http') || domain === 'localhost' || domain === '127.0.0.1') {
    return lightweightScan(url);
  }

  try {
    const { chromium } = await import('playwright');
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({
      userAgent: 'Mozilla/5.0 (compatible; AI-NMS-Scanner/1.0)',
      ignoreHTTPSErrors: true,
    });

    const page = await context.newPage();
    const collectedScripts: string[] = [];
    const mixedContentUrls: string[] = [];

    // Intercept requests to collect scripts and mixed content
    page.on('request', req => {
      const reqUrl = req.url();
      if (req.resourceType() === 'script') collectedScripts.push(reqUrl);
      if (url.startsWith('https://') && reqUrl.startsWith('http://')) {
        mixedContentUrls.push(reqUrl);
      }
    });

    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 12000 });
    } catch {
      // Page may have blocked or timed out — still collect what we have
    }

    // ── Collect real cookies ──
    const rawCookies = await context.cookies();
    const cookies: SandboxCookie[] = rawCookies.map(c => ({
      name: c.name,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite || 'None',
    }));

    // ── Collect inline script patterns (same logic as extension) ──
    const suspiciousPatterns: string[] = [];
    let hasPassword = false;
    let httpResources = 0;
    let inlineForms: { action: string }[] = [];
    try {
      const pageData = await page.evaluate(() => {
        const inlinePatterns: string[] = [];
        document.querySelectorAll('script:not([src])').forEach(s => {
          const t = s.textContent || '';
          if (t.includes('document.write(') && !inlinePatterns.includes('document.write')) inlinePatterns.push('document.write');
          if (/\binnerHTML\s*=/.test(t) && !inlinePatterns.includes('innerHTML_assign')) inlinePatterns.push('innerHTML_assign');
          if (t.includes('eval(') && !inlinePatterns.includes('eval')) inlinePatterns.push('eval');
          if (t.includes('atob(') && !inlinePatterns.includes('atob')) inlinePatterns.push('atob');
        });
        const httpRes = Array.from(document.querySelectorAll(
          'img[src^="http:"], script[src^="http:"], link[href^="http:"], iframe[src^="http:"]'
        )).length;
        const forms = Array.from(document.forms).map(f => ({ action: f.action || '' }));
        return {
          inlinePatterns,
          hasPassword: !!document.querySelector('input[type="password"]'),
          httpResources: httpRes,
          forms,
        };
      });
      suspiciousPatterns.push(...pageData.inlinePatterns);
      hasPassword = pageData.hasPassword;
      httpResources = pageData.httpResources;
      inlineForms = pageData.forms;
    } catch {}

    // ── Fetch real HTTP response headers (same as extension) ──
    let headers: Record<string, string> = {};
    try {
      const headRes = await fetch(url, { method: 'HEAD', cache: 'no-store',
        signal: AbortSignal.timeout(5000) });
      headRes.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    } catch {
      // HEAD blocked — try GET with range
      try {
        const getRes = await fetch(url, { method: 'GET', cache: 'no-store',
          headers: { Range: 'bytes=0-0' }, signal: AbortSignal.timeout(5000) });
        getRes.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
      } catch {}
    }

    await browser.close();

    // ── Score — identical logic to extension's realScore() ──
    let risk = 0;
    const threats: SandboxThreat[] = [];
    const urlL = url.toLowerCase();
    const isHttps = url.startsWith('https://');

    // 1. HTTPS
    if (!isHttps) {
      risk += 40;
      threats.push({ level: 'critical', text: 'No HTTPS — all data sent in plain text' });
    }

    // 2. Password field on HTTP
    if (hasPassword && !isHttps) {
      risk += 40;
      threats.push({ level: 'critical', text: 'Login form on HTTP page — passwords transmitted unencrypted' });
    }

    // 3. Cookie flags — session/auth cookies only (same filter as extension)
    const sessionCookies = cookies.filter(c =>
      c.name.toLowerCase().includes('session') ||
      c.name.toLowerCase().includes('token') ||
      c.name.toLowerCase().includes('auth') ||
      c.name.toLowerCase().includes('sid')
    );
    const insecureSession = sessionCookies.filter(c => !c.secure && isHttps);
    if (insecureSession.length > 0) {
      risk += 25;
      threats.push({ level: 'high', text: `${insecureSession.length} session/auth cookie(s) missing Secure flag` });
    }
    const noHttpOnly = sessionCookies.filter(c => !c.httpOnly);
    if (noHttpOnly.length > 0) {
      risk += 15;
      threats.push({ level: 'medium', text: `${noHttpOnly.length} session cookie(s) readable by JavaScript — XSS risk` });
    }
    // Flag cookies with no SameSite or SameSite=None (allows cross-site)
    const missingSameSite = cookies.filter(c =>
      !c.sameSite || c.sameSite.toLowerCase() === 'none'
    );
    if (missingSameSite.length > 0) {
      risk += 10;
      threats.push({ level: 'low', text: `${missingSameSite.length} cookie(s) missing SameSite — CSRF risk` });
    }

    // 4. Security headers (same checks as extension)
    if (Object.keys(headers).length > 0) {
      if (!headers['content-security-policy'] && !headers['x-content-security-policy']) {
        risk += 10;
        threats.push({ level: 'medium', text: 'Missing Content-Security-Policy header — XSS protection not enforced' });
      }
      if (!headers['x-frame-options'] && !headers['content-security-policy']?.includes('frame-ancestors')) {
        risk += 8;
        threats.push({ level: 'low', text: 'Missing X-Frame-Options — page may be embeddable in iframes (clickjacking risk)' });
      }
      if (!headers['x-content-type-options']) {
        risk += 5;
        threats.push({ level: 'low', text: 'Missing X-Content-Type-Options — MIME sniffing attacks possible' });
      }
      if (isHttps && !headers['strict-transport-security']) {
        risk += 5;
        threats.push({ level: 'low', text: 'Missing HSTS header — browser may allow HTTP downgrade attacks' });
      }
    }

    // 5. Mixed content
    if (isHttps && (mixedContentUrls.length > 0 || httpResources > 0)) {
      const count = mixedContentUrls.length || httpResources;
      risk += 15;
      threats.push({ level: 'high', text: `${count} HTTP resource(s) loaded on HTTPS page — mixed content` });
    }

    // 6. Forms submitting to HTTP
    const insecureForms = inlineForms.filter(f =>
      f.action && f.action.startsWith('http://') && !f.action.startsWith('http://localhost')
    );
    if (insecureForms.length > 0) {
      risk += 20;
      threats.push({ level: 'high', text: `${insecureForms.length} form(s) POST to HTTP endpoint — data sent unencrypted` });
    }

    // 7. Phishing URL patterns
    for (const { p, exclude } of PHISH_PATTERNS) {
      if (urlL.includes(p) && (!exclude || !urlL.includes(exclude))) {
        risk += 45;
        threats.push({ level: 'critical', text: `Phishing URL pattern detected: "${p}" in domain` });
        break;
      }
    }

    // 8. Known malicious domains
    if (MALICIOUS_DOMAINS.some(d => domain.includes(d))) {
      risk += 60;
      threats.push({ level: 'critical', text: `Domain "${domain}" matches known malicious domain list` });
    }

    // 9. Inline script dangerous patterns
    if (suspiciousPatterns.includes('document.write')) {
      risk += 8;
      threats.push({ level: 'medium', text: 'document.write() found in inline script — potential DOM injection vector' });
    }
    if (suspiciousPatterns.includes('innerHTML_assign')) {
      risk += 8;
      threats.push({ level: 'medium', text: 'innerHTML assignment found in inline script — potential XSS vector' });
    }
    if (suspiciousPatterns.includes('eval')) {
      risk += 10;
      threats.push({ level: 'medium', text: 'eval() found in inline script — potential code injection vector' });
    }

    risk = Math.min(100, Math.max(0, risk));

    // ── Groq AI enrichment (same as extension) ──
    let finalRisk = risk;
    let finalThreats = [...threats];
    let recommendations: string[] = [];

    try {
      const groqKey = process.env.GROQ_API_KEY;
      if (groqKey) {
        const aiRes = await fetch(`${process.env.NEXT_PUBLIC_BASE_URL || (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : 'http://localhost:3000')}/api/groq-analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url, domain,
            htmlSnippet: '',
            cookies: cookies.map(c => ({ name: c.name, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite })),
            scripts: [],
            forms: inlineForms,
            localRisk: risk,
            localThreats: threats.map(t => t.text),
          }),
        });
        const ai = await aiRes.json();
        if (ai.success) {
          // Add AI threats not already covered
          const newThreats = (ai.threats || [])
            .filter((t: string | { text: string }) => {
              const txt = (typeof t === 'string' ? t : t.text || '').toLowerCase();
              return !threats.some(lt => {
                const ltxt = lt.text.toLowerCase();
                return ltxt.includes(txt.substring(0, 25)) || txt.includes(ltxt.substring(0, 25));
              });
            })
            .map((t: string | { text: string }) => ({
              level: 'medium' as const,
              text: typeof t === 'string' ? t : t.text,
            }));
          finalThreats = [...threats, ...newThreats];
          // AI can add max +15 to local score
          const aiBoost = Math.min(15, (ai.riskScore || 0) * 0.15);
          finalRisk = Math.min(100, risk + aiBoost);
          recommendations = ai.recommendations || [];
        }
      }
    } catch {}

    finalRisk = Math.round(finalRisk);
    const securityScore = Math.max(0, 100 - finalRisk);

    if (recommendations.length === 0) {
      if (finalRisk >= 60) recommendations.push('Do not proceed — high security risk detected');
      else if (finalRisk >= 35) recommendations.push('Proceed with caution — security issues found');
      else recommendations.push('No critical issues found');
    }

    return {
      url, domain,
      scripts: collectedScripts.slice(0, 20),
      cookies,
      scriptsCount: collectedScripts.length,
      cookiesCount: cookies.length,
      mixedContent: mixedContentUrls.length || httpResources,
      suspiciousPatterns,
      sandboxRiskScore: risk,
      riskScore: finalRisk,
      securityScore,
      threats: finalThreats,
      severity: severityFromRisk(finalRisk),
      recommendations,
      sandboxVerdict: verdictFromRisk(finalRisk),
      timestamp: new Date().toISOString(),
    };

  } catch {
    // Playwright unavailable — fall back to lightweight scan
    return lightweightScan(url);
  }
}
