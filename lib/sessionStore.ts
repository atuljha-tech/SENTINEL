// ============================================================
// GLOBAL IN-MEMORY SESSION STORE
// All data lives here while the server is running.
// No database required.
// ============================================================

import { randomUUID } from 'crypto';

export interface TrafficLog {
  id: string;
  timestamp: string;
  ip: string;
  port: number;
  protocol: string;
  requestCount: number;
  userAgent: string;
  source: string;
  riskScore?: number;
  threatStatus?: string;
  attackType?: string;
  alertFlag?: boolean;
  analyzedAt?: string;
  aiReason?: string;
}

export interface DetectionResult {
  id: string;
  trafficId: string;
  timestamp: string;
  ip: string;
  port: number;
  protocol: string;
  requestCount: number;
  riskScore: number;
  threatStatus: 'Normal' | 'Suspicious' | 'Attack';
  attackType: string;
  alertFlag: boolean;
  reasons: string[];
  recommendations: string[];
}

export interface WebsiteScan {
  id: string;
  timestamp: string;
  domain: string;
  url: string;
  securityScore: number;
  riskScore: number;
  threats: string[];
  recommendations: string[];
  summary: string;
  attackType: string;
  severity: string;
  cookiesCount: number;
  scriptsCount: number;
}

export interface Alert {
  id: string;
  timestamp: string;
  domain: string;
  riskScore: number;
  threats: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  type: 'network' | 'website';
  ip?: string;
  attackType?: string;
  resolved: boolean;
}

export interface ResponseLog {
  id: string;
  timestamp: string;
  ip: string;
  attackType: string;
  riskScore: number;
  threatStatus: string;
  action: string;
  reason: string;
  severity: string;
  autoExecuted: boolean;
}

export interface BlockedIP {
  ip: string;
  blockedAt: string;
  reason: string;
  attackType: string;
  riskScore: number;
}

export interface RecentSite {
  id: string;
  url: string;
  domain: string;
  riskScore: number;
  securityScore: number;
  threats: string[];
  timestamp: string;
  sandboxVerdict: 'safe' | 'warning' | 'block';
}

export interface CivicAuditLog {
  id: string;
  timestamp: string;
  tool: string;
  params: Record<string, unknown>;
  result: 'allowed' | 'blocked' | 'error';
  reason: string;
  civicCallId?: string;
  civicConnected: boolean;
}

// ── Global stores (module-level = persists across requests) ──
const MAX = 500;

function cap<T>(arr: T[]): T[] {
  return arr.length > MAX ? arr.slice(0, MAX) : arr;
}

class SessionStore {
  trafficLogs:      TrafficLog[]      = [];
  detectionResults: DetectionResult[] = [];
  websiteScans:     WebsiteScan[]     = [];
  alerts:           Alert[]           = [];
  responseLogs:     ResponseLog[]     = [];
  blockedIPs:       BlockedIP[]       = [];
  civicAuditLogs:   CivicAuditLog[]   = [];
  recentSites:      RecentSite[]      = [];
  civicStats = { block_ip: 0, rate_limit_ip: 0, scan_website: 0, log_security_event: 0, retrieve_recent_threats: 0 };

  // ── Traffic ──
  addTraffic(data: Omit<TrafficLog, 'id' | 'timestamp'>): TrafficLog {
    const entry: TrafficLog = { id: randomUUID(), timestamp: new Date().toISOString(), ...data };
    this.trafficLogs.unshift(entry);
    this.trafficLogs = cap(this.trafficLogs);
    return entry;
  }

  getTraffic(limit = 100): TrafficLog[] {
    return this.trafficLogs.slice(0, limit);
  }

  updateTraffic(id: string, updates: Partial<TrafficLog>) {
    const idx = this.trafficLogs.findIndex(t => t.id === id);
    if (idx !== -1) this.trafficLogs[idx] = { ...this.trafficLogs[idx], ...updates };
  }

  getUnanalyzed(limit = 20): TrafficLog[] {
    return this.trafficLogs.filter(t => t.riskScore === undefined).slice(0, limit);
  }

  // ── Detections ──
  addDetection(data: Omit<DetectionResult, 'id' | 'timestamp'>): DetectionResult {
    const entry: DetectionResult = { id: randomUUID(), timestamp: new Date().toISOString(), ...data };
    this.detectionResults.unshift(entry);
    this.detectionResults = cap(this.detectionResults);
    // Auto-create alert if high risk
    if (entry.alertFlag && entry.riskScore >= 60) {
      this.addAlert({
        domain: entry.ip,
        riskScore: entry.riskScore,
        threats: entry.reasons,
        severity: entry.riskScore >= 80 ? 'critical' : 'high',
        type: 'network',
        ip: entry.ip,
        attackType: entry.attackType,
        resolved: false,
      });
    }
    return entry;
  }

  getAlertDetections(limit = 50): DetectionResult[] {
    return this.detectionResults.filter(d => d.alertFlag).slice(0, limit);
  }

  getDetectionStats() {
    const groups: Record<string, { count: number; totalRisk: number }> = {};
    for (const d of this.detectionResults) {
      if (!groups[d.threatStatus]) groups[d.threatStatus] = { count: 0, totalRisk: 0 };
      groups[d.threatStatus].count++;
      groups[d.threatStatus].totalRisk += d.riskScore;
    }
    return Object.entries(groups).map(([status, v]) => ({
      _id: status,
      count: v.count,
      avgRiskScore: Math.round(v.totalRisk / v.count),
    }));
  }

  // ── Website scans ──
  addWebsiteScan(data: Omit<WebsiteScan, 'id' | 'timestamp'>): WebsiteScan {
    const entry: WebsiteScan = { id: randomUUID(), timestamp: new Date().toISOString(), ...data };
    this.websiteScans.unshift(entry);
    this.websiteScans = cap(this.websiteScans);
    // Auto-create alert for high risk
    if (entry.riskScore >= 50 && entry.threats.length > 0) {
      this.addAlert({
        domain: entry.domain,
        riskScore: entry.riskScore,
        threats: entry.threats,
        severity: entry.riskScore >= 70 ? 'critical' : 'high',
        type: 'website',
        resolved: false,
      });
    }
    return entry;
  }

  getWebsiteScans(limit = 50): WebsiteScan[] {
    return this.websiteScans.slice(0, limit);
  }

  getWebsiteStats() {
    if (this.websiteScans.length === 0) return null;
    const latest = this.websiteScans[0];
    return {
      latestDomain: latest.domain,
      latestScore: latest.securityScore,
      latestRisk: latest.riskScore,
      totalScans: this.websiteScans.length,
    };
  }

  // ── Alerts ──
  addAlert(data: Omit<Alert, 'id' | 'timestamp'>): Alert {
    // Deduplicate: don't add same domain/ip alert within 30s
    const recent = this.alerts.find(a =>
      a.domain === data.domain &&
      !a.resolved &&
      Date.now() - new Date(a.timestamp).getTime() < 30000
    );
    if (recent) return recent;
    const entry: Alert = { id: randomUUID(), timestamp: new Date().toISOString(), ...data };
    this.alerts.unshift(entry);
    this.alerts = cap(this.alerts);
    return entry;
  }

  getAlerts(limit = 50): Alert[] {
    return this.alerts.filter(a => !a.resolved).slice(0, limit);
  }

  // ── Response logs ──
  addResponseLog(data: Omit<ResponseLog, 'id' | 'timestamp'>): ResponseLog {
    const entry: ResponseLog = { id: randomUUID(), timestamp: new Date().toISOString(), ...data };
    this.responseLogs.unshift(entry);
    this.responseLogs = cap(this.responseLogs);
    return entry;
  }

  getResponseLogs(limit = 50): ResponseLog[] {
    return this.responseLogs.slice(0, limit);
  }

  // ── Blocked IPs ──
  blockIP(ip: string, reason: string, attackType: string, riskScore: number) {
    if (!this.blockedIPs.find(b => b.ip === ip)) {
      this.blockedIPs.push({ ip, blockedAt: new Date().toISOString(), reason, attackType, riskScore });
    }
  }

  unblockIP(ip: string): boolean {
    const before = this.blockedIPs.length;
    this.blockedIPs = this.blockedIPs.filter(b => b.ip !== ip);
    return this.blockedIPs.length < before;
  }

  isBlocked(ip: string): boolean {
    return this.blockedIPs.some(b => b.ip === ip);
  }

  getBlockedIPs(): BlockedIP[] {
    return this.blockedIPs;
  }

  // ── Civic Audit ──
  addCivicLog(data: Omit<CivicAuditLog, 'id' | 'timestamp'>): CivicAuditLog {
    const entry: CivicAuditLog = { id: randomUUID(), timestamp: new Date().toISOString(), ...data };
    this.civicAuditLogs.unshift(entry);
    if (this.civicAuditLogs.length > 300) this.civicAuditLogs.pop();
    // Update stats
    const key = data.tool as keyof typeof this.civicStats;
    if (key in this.civicStats) this.civicStats[key]++;
    return entry;
  }

  getCivicLogs(limit = 50): CivicAuditLog[] { return this.civicAuditLogs.slice(0, limit); }
  getCivicStats() { return { ...this.civicStats }; }

  // ── Recent Sites (sandbox scans) ──
  addRecentSite(data: Omit<RecentSite, 'id'>): RecentSite {
    const entry: RecentSite = { id: randomUUID(), ...data };
    // Deduplicate by domain within 60s
    const recent = this.recentSites.find(s =>
      s.domain === data.domain &&
      Date.now() - new Date(s.timestamp).getTime() < 60000
    );
    if (recent) { Object.assign(recent, entry); return recent; }
    this.recentSites.unshift(entry);
    if (this.recentSites.length > 15) this.recentSites = this.recentSites.slice(0, 15);
    return entry;
  }

  getRecentSites(): RecentSite[] {
    return this.recentSites;
  }

  // ── Summary ──
  getSummary() {
    return {
      totalTraffic:    this.trafficLogs.length,
      totalAlerts:     this.getAlerts().length,
      totalBlocked:    this.blockedIPs.length,
      totalScans:      this.websiteScans.length,
      totalDetections: this.detectionResults.length,
    };
  }
}

// Singleton — shared across all API route invocations in the same process
const store = new SessionStore();
export default store;
export { randomUUID };
