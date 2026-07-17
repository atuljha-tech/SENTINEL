// Website Security Scanner - Analyzes websites for security risks
// This is the core scanning engine for the browser extension

export interface ScanResult {
  domain: string;
  securityScore: number;
  riskScore: number;
  threats: Threat[];
  timestamp: Date;
  cookies: CookieAnalysis;
  scripts: ScriptAnalysis;
  networkRequests: NetworkAnalysis;
}

export interface Threat {
  type: 'insecure_cookie' | 'missing_secure_flag' | 'suspicious_script' | 'malicious_domain' | 'http_request' | 'tracker' | 'mixed_content';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  recommendation: string;
}

export interface CookieAnalysis {
  total: number;
  insecure: number;
  missingHttpOnly: number;
  missingSameSite: number;
  longLived: number;
}

export interface ScriptAnalysis {
  total: number;
  external: number;
  suspicious: number;
  unminified: number;
}

export interface NetworkAnalysis {
  total: number;
  http: number;
  https: number;
  suspicious: number;
}

// Known malicious domains (for demo)
const MALICIOUS_DOMAINS = [
  'malware-tracker.com',
  'phishing-site.net',
  'suspicious-click.com',
  'fake-login.org',
  'bad-ads.net'
];

// Suspicious script patterns
const SUSPICIOUS_PATTERNS = [
  'eval(',
  'document.write',
  'escape(',
  'unescape(',
  'atob(',
  'fromCharCode',
  'setInterval',
  'setTimeout'
];

// Known trackers
const TRACKER_DOMAINS = [
  'google-analytics.com',
  'facebook.com/tr',
  'doubleclick.net',
  'googletagmanager.com',
  'hotjar.com',
  'clarity.ms',
  'mouseflow.com'
];

export class WebsiteSecurityScanner {
  
  // Main scan function
  async scanWebsite(url: string, cookies: any[], requests: any[]): Promise<ScanResult> {
    const domain = this.extractDomain(url);
    let riskScore = 0;
    const threats: Threat[] = [];
    
    // 1. Analyze Cookies
    const cookieAnalysis = this.analyzeCookies(cookies, threats);
    riskScore += cookieAnalysis.insecure * 10;
    riskScore += cookieAnalysis.missingHttpOnly * 8;
    riskScore += cookieAnalysis.missingSameSite * 5;
    riskScore += cookieAnalysis.longLived * 3;
    
    // 2. Analyze Scripts
    const scriptAnalysis = this.analyzeScripts(requests, threats);
    riskScore += scriptAnalysis.suspicious * 15;
    
    // 3. Analyze Network Requests
    const networkAnalysis = this.analyzeNetworkRequests(requests, threats);
    riskScore += networkAnalysis.http * 10;
    riskScore += networkAnalysis.suspicious * 20;
    
    // 4. Check for malicious domain
    if (this.isMaliciousDomain(domain)) {
      riskScore += 50;
      threats.push({
        type: 'malicious_domain',
        severity: 'critical',
        description: `Domain ${domain} is flagged as malicious`,
        recommendation: 'Immediately close this website and run antivirus scan'
      });
    }
    
    // 5. Check for trackers
    const trackersFound = this.detectTrackers(requests);
    riskScore += trackersFound.length * 5;
    trackersFound.forEach(tracker => {
      threats.push({
        type: 'tracker',
        severity: 'low',
        description: `Tracker detected: ${tracker}`,
        recommendation: 'Use ad-blocker or privacy-focused browser'
      });
    });
    
    // Calculate final security score (100 - riskScore, min 0, max 100)
    const securityScore = Math.max(0, Math.min(100, 100 - riskScore));
    
    return {
      domain,
      securityScore,
      riskScore: Math.min(100, riskScore),
      threats,
      timestamp: new Date(),
      cookies: cookieAnalysis,
      scripts: scriptAnalysis,
      networkRequests: networkAnalysis
    };
  }
  
  // Extract domain from URL
  private extractDomain(url: string): string {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch {
      return url;
    }
  }
  
  // Analyze cookies for security issues
  private analyzeCookies(cookies: any[], threats: Threat[]): CookieAnalysis {
    let insecure = 0;
    let missingHttpOnly = 0;
    let missingSameSite = 0;
    let longLived = 0;
    
    for (const cookie of cookies) {
      // Check for secure flag
      if (!cookie.secure) {
        insecure++;
        threats.push({
          type: 'insecure_cookie',
          severity: 'high',
          description: `Cookie "${cookie.name}" is missing Secure flag`,
          recommendation: 'Website should set Secure flag on all cookies'
        });
      }
      
      // Check for HttpOnly flag
      if (!cookie.httpOnly) {
        missingHttpOnly++;
        threats.push({
          type: 'insecure_cookie',
          severity: 'medium',
          description: `Cookie "${cookie.name}" is accessible via JavaScript (missing HttpOnly)`,
          recommendation: 'Set HttpOnly flag to prevent XSS attacks'
        });
      }
      
      // Check for SameSite
      if (!cookie.sameSite || cookie.sameSite === 'unspecified') {
        missingSameSite++;
        threats.push({
          type: 'insecure_cookie',
          severity: 'medium',
          description: `Cookie "${cookie.name}" missing SameSite attribute`,
          recommendation: 'Set SameSite=Lax or SameSite=Strict'
        });
      }
      
      // Check for long expiration
      if (cookie.expirationDate) {
        const daysUntilExpiry = (cookie.expirationDate - Date.now() / 1000) / 86400;
        if (daysUntilExpiry > 30) {
          longLived++;
        }
      }
    }
    
    return { total: cookies.length, insecure, missingHttpOnly, missingSameSite, longLived };
  }
  
  // Analyze scripts for suspicious patterns
  private analyzeScripts(requests: any[], threats: Threat[]): ScriptAnalysis {
    let suspicious = 0;
    let external = 0;
    let unminified = 0;
    
    // Filter script requests
    const scriptRequests = requests.filter(r => 
      r.url.includes('.js') || r.type === 'script'
    );
    
    external = scriptRequests.length;
    
    for (const script of scriptRequests) {
      // Check for suspicious patterns in URL
      for (const pattern of SUSPICIOUS_PATTERNS) {
        if (script.url.toLowerCase().includes(pattern.toLowerCase())) {
          suspicious++;
          threats.push({
            type: 'suspicious_script',
            severity: 'high',
            description: `Suspicious script detected: ${script.url.substring(0, 50)}...`,
            recommendation: 'Block this script and scan for malware'
          });
          break;
        }
      }
    }
    
    return { total: scriptRequests.length, external, suspicious, unminified };
  }
  
  // Analyze network requests
  private analyzeNetworkRequests(requests: any[], threats: Threat[]): NetworkAnalysis {
    let http = 0;
    let suspicious = 0;
    
    for (const req of requests) {
      // Check for HTTP (insecure)
      if (req.url.startsWith('http://')) {
        http++;
        threats.push({
          type: 'http_request',
          severity: 'medium',
          description: `Insecure HTTP request to: ${req.url.substring(0, 60)}`,
          recommendation: 'Website should use HTTPS for all resources'
        });
      }
      
      // Check for mixed content
      if (req.url.startsWith('http://') && req.initiator?.url?.startsWith('https://')) {
        threats.push({
          type: 'mixed_content',
          severity: 'high',
          description: `Mixed content: HTTPS page loading HTTP resource`,
          recommendation: 'Upgrade all resources to HTTPS'
        });
      }
    }
    
    return { total: requests.length, http, https: requests.length - http, suspicious };
  }
  
  // Check if domain is malicious
  private isMaliciousDomain(domain: string): boolean {
    return MALICIOUS_DOMAINS.some(malicious => 
      domain.includes(malicious) || malicious.includes(domain)
    );
  }
  
  // Detect trackers
  private detectTrackers(requests: any[]): string[] {
    const trackers: string[] = [];
    
    for (const req of requests) {
      for (const tracker of TRACKER_DOMAINS) {
        if (req.url.toLowerCase().includes(tracker)) {
          trackers.push(tracker);
          break;
        }
      }
    }
    
    return [...new Set(trackers)];
  }
  
  // Get risk level label
  getRiskLevel(riskScore: number): string {
    if (riskScore >= 70) return 'CRITICAL';
    if (riskScore >= 50) return 'HIGH';
    if (riskScore >= 30) return 'MEDIUM';
    if (riskScore >= 10) return 'LOW';
    return 'SAFE';
  }
  
  // Get risk color
  getRiskColor(riskScore: number): string {
    if (riskScore >= 70) return '#ef4444';
    if (riskScore >= 50) return '#f97316';
    if (riskScore >= 30) return '#eab308';
    if (riskScore >= 10) return '#3b82f6';
    return '#22c55e';
  }
}

export const websiteScanner = new WebsiteSecurityScanner();