// ============================================================
// SENTINEL THREAT REGISTRY
// Community-sourced malicious URL/IP database.
// Any agent can report or query the registry.
// Foundation for future on-chain threat registry.
// ============================================================

import { randomUUID } from 'crypto';

export type ThreatCategory =
  | 'phishing'
  | 'wallet_drainer'
  | 'defi_scam'
  | 'malware'
  | 'ransomware'
  | 'ddos_source'
  | 'credential_theft'
  | 'unknown';

export interface RegistryEntry {
  id:            string;
  type:          'url' | 'ip' | 'domain';
  value:         string;
  category:      ThreatCategory;
  riskScore:     number;
  reportedBy:    string; // agentId or 'community'
  reportCount:   number;
  confirmedBy:   string[];
  firstReported: string;
  lastReported:  string;
  description:   string;
  tags:          string[];
}

class ThreatRegistryStore {
  private entries: Map<string, RegistryEntry> = new Map();

  constructor() {
    // Seed with known threats
    const seeds: Omit<RegistryEntry, 'id' | 'firstReported' | 'lastReported'>[] = [
      {
        type: 'domain', value: 'login-verify-account.com',
        category: 'phishing', riskScore: 95,
        reportedBy: 'sentinel-scanner', reportCount: 14,
        confirmedBy: ['sentinel-scanner', 'community'],
        description: 'Phishing domain impersonating account verification portals',
        tags: ['phishing', 'credential-theft'],
      },
      {
        type: 'domain', value: 'paypal-secure-login.com',
        category: 'phishing', riskScore: 98,
        reportedBy: 'sentinel-scanner', reportCount: 31,
        confirmedBy: ['sentinel-scanner'],
        description: 'PayPal credential harvesting site',
        tags: ['phishing', 'paypal', 'credential-theft'],
      },
      {
        type: 'ip', value: '45.33.22.11',
        category: 'ddos_source', riskScore: 87,
        reportedBy: 'sentinel-scanner', reportCount: 7,
        confirmedBy: ['sentinel-scanner'],
        description: 'Known DDoS botnet C2 node',
        tags: ['ddos', 'botnet'],
      },
      {
        type: 'ip', value: '185.130.5.253',
        category: 'malware', riskScore: 95,
        reportedBy: 'sentinel-scanner', reportCount: 22,
        confirmedBy: ['sentinel-scanner', 'community'],
        description: 'Ransomware distribution server',
        tags: ['malware', 'ransomware'],
      },
      {
        type: 'domain', value: 'uniswap-claim-airdrop.com',
        category: 'wallet_drainer', riskScore: 99,
        reportedBy: 'defi-agent', reportCount: 45,
        confirmedBy: ['defi-agent', 'community'],
        description: 'Fake Uniswap airdrop — wallet drainer contract',
        tags: ['defi', 'wallet-drainer', 'uniswap-phishing'],
      },
    ];

    seeds.forEach(s => {
      const id = randomUUID();
      this.entries.set(s.value.toLowerCase(), {
        id,
        firstReported: new Date(Date.now() - Math.random() * 30 * 86400000).toISOString(),
        lastReported:  new Date().toISOString(),
        ...s,
      });
    });
  }

  check(value: string): RegistryEntry | null {
    const normalized = value.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    // Exact match
    if (this.entries.has(normalized)) return this.entries.get(normalized)!;
    // Substring match for domains
    for (const [key, entry] of this.entries.entries()) {
      if (normalized.includes(key) || key.includes(normalized)) {
        return entry;
      }
    }
    return null;
  }

  report(data: {
    type: 'url' | 'ip' | 'domain';
    value: string;
    category: ThreatCategory;
    riskScore: number;
    reportedBy: string;
    description: string;
    tags?: string[];
  }): RegistryEntry {
    const normalized = data.value.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    const existing = this.entries.get(normalized);

    if (existing) {
      existing.reportCount++;
      existing.lastReported = new Date().toISOString();
      if (!existing.confirmedBy.includes(data.reportedBy)) {
        existing.confirmedBy.push(data.reportedBy);
      }
      if (data.riskScore > existing.riskScore) existing.riskScore = data.riskScore;
      return existing;
    }

    const entry: RegistryEntry = {
      id:            randomUUID(),
      type:          data.type,
      value:         normalized,
      category:      data.category,
      riskScore:     data.riskScore,
      reportedBy:    data.reportedBy,
      reportCount:   1,
      confirmedBy:   [data.reportedBy],
      firstReported: new Date().toISOString(),
      lastReported:  new Date().toISOString(),
      description:   data.description,
      tags:          data.tags ?? [],
    };

    this.entries.set(normalized, entry);
    return entry;
  }

  getAll(limit = 50): RegistryEntry[] {
    return Array.from(this.entries.values())
      .sort((a, b) => b.reportCount - a.reportCount)
      .slice(0, limit);
  }

  getStats() {
    const all = Array.from(this.entries.values());
    const byCategory: Record<string, number> = {};
    all.forEach(e => { byCategory[e.category] = (byCategory[e.category] ?? 0) + 1; });
    return {
      total:        all.length,
      totalReports: all.reduce((s, e) => s + e.reportCount, 0),
      byCategory,
      topThreats:   all.sort((a, b) => b.riskScore - a.riskScore).slice(0, 5),
    };
  }
}

const threatRegistry = new ThreatRegistryStore();
export default threatRegistry;
