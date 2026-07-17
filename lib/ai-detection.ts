// Agentic AI Detection Engine
// This is the BRAIN of your system - REAL-TIME RISK CALCULATION

export interface TrafficLog {
  _id?: string;
  ip: string;
  port: number;
  protocol: string;
  requestCount: number;
  timestamp: Date;
  userAgent?: string;
}

export interface DetectionResult {
  riskScore: number;        // 0-100
  threatStatus: 'Normal' | 'Suspicious' | 'Attack';
  attackType: 'None' | 'DDoS' | 'Brute Force' | 'Bot Traffic' | 'Port Scan' | 'Unknown Intrusion';
  alertFlag: boolean;
  reasons: string[];
  recommendations: string[];
}

// Known malicious IPs (threat intelligence feed)
const KNOWN_MALICIOUS_IPS = [
  '45.33.22.11', '103.45.67.89', '185.130.5.253',
  '94.102.61.78', '193.42.56.78', '5.188.86.45',
  '91.200.12.101', '185.220.101.1'
];

// Safe/whitelisted IPs
const TRUSTED_IPS = [
  '8.8.8.8', '1.1.1.1', '192.168.1.1', '10.0.0.1'
];

// Suspicious ports (commonly targeted in attacks)
const DANGEROUS_PORTS = [22, 23, 445, 3389, 1433, 3306, 5900, 6379, 27017];
const SUSPICIOUS_PORTS = [80, 443, 8080, 8443, 53, 25, 110, 993, 995];

// Store recent traffic for pattern analysis
let recentTrafficHistory: TrafficLog[] = [];
const MAX_HISTORY = 100;

// ============================================
// REAL RISK SCORE CALCULATION
// ============================================
export function calculateRealRiskScore(traffic: TrafficLog, allTraffic: TrafficLog[]): number {
  let score = 0;
  
  // 1. REQUEST VOLUME ANALYSIS
  if (traffic.requestCount > 100) {
    score += 40;
  } else if (traffic.requestCount > 50) {
    score += 20;
  } else if (traffic.requestCount > 30) {
    score += 10;
  }
  
  // 2. THREAT INTELLIGENCE CHECK
  if (KNOWN_MALICIOUS_IPS.includes(traffic.ip)) {
    score += 50;
  }
  
  // 3. TRUSTED IPs (reduce risk)
  if (TRUSTED_IPS.includes(traffic.ip)) {
    score = Math.max(0, score - 30);
  }
  
  // 4. PORT ANALYSIS
  if (DANGEROUS_PORTS.includes(traffic.port)) {
    score += 25;
  } else if (SUSPICIOUS_PORTS.includes(traffic.port)) {
    score += 10;
  }
  
  // 5. RATE OF REQUESTS (Brute Force / DDoS pattern)
  const oneMinuteAgo = new Date(Date.now() - 60000);
  const recentFromSameIP = allTraffic.filter(t => 
    t.ip === traffic.ip && 
    new Date(t.timestamp) >= oneMinuteAgo
  ).length;
  
  if (recentFromSameIP > 20) {
    score += 35;
  } else if (recentFromSameIP > 10) {
    score += 20;
  } else if (recentFromSameIP > 5) {
    score += 10;
  }
  
  // 6. UNIQUE IPs ON SAME PORT (DDoS pattern)
  const uniqueIPsOnPort = new Set(
    allTraffic.filter(t => t.port === traffic.port).map(t => t.ip)
  ).size;
  
  if (uniqueIPsOnPort > 20) {
    score += 30;
  } else if (uniqueIPsOnPort > 10) {
    score += 15;
  }
  
  // 7. RAPID REQUEST PATTERN (Bot detection)
  const timestamps = allTraffic.filter(t => t.ip === traffic.ip).map(t => new Date(t.timestamp).getTime());
  const rapidRequests = timestamps.filter((t, i, arr) => 
    i > 0 && (t - arr[i-1]) < 100
  ).length;
  
  if (rapidRequests > 5) {
    score += 20;
  }
  
  // 8. NEW/UNKNOWN IP (first time seen)
  const seenIPs = new Set(allTraffic.map(t => t.ip));
  if (!seenIPs.has(traffic.ip) && allTraffic.length > 10) {
    score += 15;
  }
  
  // Normalize score to 0-100
  return Math.min(100, Math.max(0, score));
}

// ============================================
// ATTACK TYPE CLASSIFICATION
// ============================================
export function classifyAttackType(traffic: TrafficLog, riskScore: number, allTraffic: TrafficLog[]): DetectionResult['attackType'] {
  // Check for malicious IP first
  if (KNOWN_MALICIOUS_IPS.includes(traffic.ip)) {
    return 'Unknown Intrusion';
  }
  
  // DDoS: High request count or many unique IPs on same port
  const uniqueIPsOnPort = new Set(allTraffic.filter(t => t.port === traffic.port).map(t => t.ip)).size;
  if (traffic.requestCount > 100 || uniqueIPsOnPort > 15) {
    return 'DDoS';
  }
  
  // Brute Force: Many requests from same IP in short time
  const oneMinuteAgo = new Date(Date.now() - 60000);
  const recentFromSameIP = allTraffic.filter(t => 
    t.ip === traffic.ip && new Date(t.timestamp) >= oneMinuteAgo
  ).length;
  if (recentFromSameIP > 10) {
    return 'Brute Force';
  }
  
  // Port Scan: Suspicious port patterns
  if (DANGEROUS_PORTS.includes(traffic.port) || SUSPICIOUS_PORTS.includes(traffic.port)) {
    return 'Port Scan';
  }
  
  // Bot Traffic: Rapid requests pattern
  const timestamps = allTraffic.filter(t => t.ip === traffic.ip).map(t => new Date(t.timestamp).getTime());
  const rapidRequests = timestamps.filter((t, i, arr) => i > 0 && (t - arr[i-1]) < 100).length;
  if (rapidRequests > 3) {
    return 'Bot Traffic';
  }
  
  return 'None';
}

// ============================================
// GENERATE RECOMMENDATIONS
// ============================================
export function generateRecommendations(attackType: DetectionResult['attackType'], riskScore: number): string[] {
  const recommendations: string[] = [];
  
  if (attackType === 'DDoS') {
    recommendations.push('🛡️ Enable rate limiting on your server');
    recommendations.push('🛡️ Use a CDN with DDoS protection (Cloudflare, AWS Shield)');
    recommendations.push('🛡️ Block attacking IP ranges at firewall level');
  } else if (attackType === 'Brute Force') {
    recommendations.push('🔐 Implement account lockout after 5 failed attempts');
    recommendations.push('🔐 Use CAPTCHA for login attempts');
    recommendations.push('🔐 Enable two-factor authentication (2FA)');
  } else if (attackType === 'Bot Traffic') {
    recommendations.push('🤖 Add CAPTCHA to all forms');
    recommendations.push('🤖 Implement bot detection using behavioral analysis');
    recommendations.push('🤖 Rate limit API endpoints');
  } else if (attackType === 'Port Scan') {
    recommendations.push('🔒 Use a firewall to block suspicious ports');
    recommendations.push('🔒 Implement port knocking for sensitive services');
    recommendations.push('🔒 Use an IDS/IPS system (Snort, Suricata)');
  } else if (riskScore >= 35) {
    recommendations.push('👁️ Monitor this IP address closely for 24 hours');
    recommendations.push('👁️ Review logs for related activity');
  } else {
    recommendations.push('✅ No action needed - traffic appears normal');
    recommendations.push('✅ Continue monitoring as part of routine security');
  }
  
  return recommendations;
}

// ============================================
// ROUND SCORE HELPER
// ============================================
function roundScore(score: number): number {
  return Math.round(score * 10) / 10;
}

// ============================================
// MAIN DETECTION CLASS (EXPORTED)
// ============================================
export class AgenticAIDetector {
  
  // Main detection function - called for every traffic log
  detect(traffic: TrafficLog, allTraffic: TrafficLog[]): DetectionResult {
    const riskScore = roundScore(calculateRealRiskScore(traffic, allTraffic));
    
    // Determine threat status
    let threatStatus: DetectionResult['threatStatus'];
    let alertFlag: boolean;
    
    if (riskScore >= 70) {
      threatStatus = 'Attack';
      alertFlag = true;
    } else if (riskScore >= 35) {
      threatStatus = 'Suspicious';
      alertFlag = true;
    } else {
      threatStatus = 'Normal';
      alertFlag = false;
    }
    
    // Classify attack type
    const attackType = classifyAttackType(traffic, riskScore, allTraffic);
    
    // Generate recommendations
    const recommendations = generateRecommendations(attackType, riskScore);
    
    // Build reasons list
    const reasons: string[] = [];
    if (traffic.requestCount > 100) reasons.push(`High volume: ${traffic.requestCount} requests`);
    if (KNOWN_MALICIOUS_IPS.includes(traffic.ip)) reasons.push(`Known malicious IP: ${traffic.ip}`);
    if (DANGEROUS_PORTS.includes(traffic.port)) reasons.push(`Dangerous port: ${traffic.port}`);
    if (reasons.length === 0) reasons.push('Normal traffic pattern');
    
    return {
      riskScore,
      threatStatus,
      attackType,
      alertFlag,
      reasons,
      recommendations
    };
  }
  
  // Update traffic history
  updateHistory(traffic: TrafficLog) {
    recentTrafficHistory.unshift(traffic);
    if (recentTrafficHistory.length > MAX_HISTORY) {
      recentTrafficHistory.pop();
    }
  }
  
  // Get recent history
  getHistory(): TrafficLog[] {
    return recentTrafficHistory;
  }
  
  // Get current threat level
  getCurrentThreatLevel(): string {
    const recentHighRisk = recentTrafficHistory.filter(t => {
      const score = calculateRealRiskScore(t, recentTrafficHistory);
      return score >= 70;
    }).length;
    
    if (recentHighRisk > 10) return 'CRITICAL';
    if (recentHighRisk > 5) return 'HIGH';
    if (recentHighRisk > 0) return 'MEDIUM';
    return 'LOW';
  }
}

// ============================================
// CREATE AND EXPORT SINGLETON INSTANCE
// ============================================
export const aiDetector = new AgenticAIDetector();