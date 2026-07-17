// ============================================================
// SENTINEL USAGE TRACKER & API KEY MANAGEMENT
// Revenue model foundation — tracks agent API key usage,
// enforces tier limits, and generates billing metrics.
// ============================================================

import { randomUUID } from 'crypto';

export type Tier = 'free' | 'pro' | 'team' | 'enterprise';

export interface AgentKey {
  key:       string;
  agentId:   string;
  tier:      Tier;
  createdAt: string;
  label:     string;
}

export interface UsageRecord {
  id:           string;
  agentKey:     string;
  agentId:      string;
  tool:         string;
  timestamp:    string;
  tier:         Tier;
  billableUnits: number;
  latencyMs:    number;
  success:      boolean;
}

export interface TierLimits {
  scansPerMonth:  number;
  agentKeys:      number;
  auditExport:    boolean;
  priorityQueue:  boolean;
  telegramBot:    boolean;
  modelRouting:   boolean;
}

const TIER_CONFIG: Record<Tier, TierLimits & { priceUsd: number; label: string }> = {
  free: {
    scansPerMonth: 50,
    agentKeys:     1,
    auditExport:   false,
    priorityQueue: false,
    telegramBot:   false,
    modelRouting:  false,
    priceUsd:      0,
    label:         'Free',
  },
  pro: {
    scansPerMonth: 500,
    agentKeys:     5,
    auditExport:   true,
    priorityQueue: false,
    telegramBot:   false,
    modelRouting:  true,
    priceUsd:      29,
    label:         'Pro',
  },
  team: {
    scansPerMonth: 5000,
    agentKeys:     25,
    auditExport:   true,
    priorityQueue: true,
    telegramBot:   true,
    modelRouting:  true,
    priceUsd:      99,
    label:         'Team',
  },
  enterprise: {
    scansPerMonth: Infinity,
    agentKeys:     Infinity,
    auditExport:   true,
    priorityQueue: true,
    telegramBot:   true,
    modelRouting:  true,
    priceUsd:      0, // custom
    label:         'Enterprise',
  },
};

// ── In-memory store (swap for Supabase/Postgres in prod) ──────
class UsageStore {
  private keys: Map<string, AgentKey> = new Map();
  private usage: UsageRecord[]        = [];

  constructor() {
    // Pre-seed a demo key so the UI works on first load
    const demoKey = 'sk-sentinel-demo0000';
    this.keys.set(demoKey, {
      key:       demoKey,
      agentId:   'demo-agent',
      tier:      'free',
      createdAt: new Date().toISOString(),
      label:     'Demo Key',
    });
    const proKey = 'sk-sentinel-pro00000';
    this.keys.set(proKey, {
      key:       proKey,
      agentId:   'pro-agent-001',
      tier:      'pro',
      createdAt: new Date().toISOString(),
      label:     'Pro Demo',
    });
  }

  // ── Key management ──────────────────────────────────────────
  createKey(agentId: string, tier: Tier, label: string): AgentKey {
    const key: AgentKey = {
      key:       `sk-sentinel-${randomUUID().replace(/-/g, '').slice(0, 16)}`,
      agentId,
      tier,
      createdAt: new Date().toISOString(),
      label,
    };
    this.keys.set(key.key, key);
    return key;
  }

  validateKey(key: string): AgentKey | null {
    return this.keys.get(key) ?? null;
  }

  getAllKeys(): AgentKey[] {
    return Array.from(this.keys.values());
  }

  // ── Usage tracking ──────────────────────────────────────────
  record(data: Omit<UsageRecord, 'id' | 'timestamp'>): UsageRecord {
    const entry: UsageRecord = {
      id:        randomUUID(),
      timestamp: new Date().toISOString(),
      ...data,
    };
    this.usage.unshift(entry);
    if (this.usage.length > 10000) this.usage.pop();
    return entry;
  }

  getUsageForKey(agentKey: string, sinceMs = 30 * 24 * 60 * 60 * 1000): UsageRecord[] {
    const since = Date.now() - sinceMs;
    return this.usage
      .filter(u => u.agentKey === agentKey && new Date(u.timestamp).getTime() > since);
  }

  // ── Rate limiting ───────────────────────────────────────────
  checkLimit(agentKey: string): { allowed: boolean; reason?: string; remaining: number } {
    const keyData = this.keys.get(agentKey);
    if (!keyData) return { allowed: false, reason: 'Invalid API key', remaining: 0 };

    const limits = TIER_CONFIG[keyData.tier];
    const monthStart = new Date();
    monthStart.setDate(1); monthStart.setHours(0, 0, 0, 0);

    const usedThisMonth = this.usage.filter(
      u => u.agentKey === agentKey && new Date(u.timestamp) >= monthStart
    ).length;

    const remaining = Math.max(0, limits.scansPerMonth - usedThisMonth);

    if (usedThisMonth >= limits.scansPerMonth) {
      return {
        allowed: false,
        reason:  `Monthly limit reached (${limits.scansPerMonth} scans on ${keyData.tier} tier). Upgrade at sentinel.vercel.app/upgrade`,
        remaining: 0,
      };
    }

    return { allowed: true, remaining };
  }

  // ── Revenue metrics ─────────────────────────────────────────
  getMetrics() {
    const allKeys    = Array.from(this.keys.values());
    const now        = Date.now();
    const last24h    = now - 24 * 60 * 60 * 1000;
    const last30d    = now - 30 * 24 * 60 * 60 * 1000;

    const activeKeys = allKeys.filter(k => {
      const lastUsed = this.usage.find(u => u.agentKey === k.key);
      return lastUsed && new Date(lastUsed.timestamp).getTime() > last30d;
    });

    const callsToday  = this.usage.filter(u => new Date(u.timestamp).getTime() > last24h).length;
    const callsMonth  = this.usage.filter(u => new Date(u.timestamp).getTime() > last30d).length;

    // MRR projection: sum of tier prices for active paying keys
    const mrr = activeKeys.reduce((sum, k) => {
      return sum + TIER_CONFIG[k.tier].priceUsd;
    }, 0);

    const tierBreakdown = {
      free:       allKeys.filter(k => k.tier === 'free').length,
      pro:        allKeys.filter(k => k.tier === 'pro').length,
      team:       allKeys.filter(k => k.tier === 'team').length,
      enterprise: allKeys.filter(k => k.tier === 'enterprise').length,
    };

    // Top tools
    const toolCounts: Record<string, number> = {};
    this.usage.forEach(u => { toolCounts[u.tool] = (toolCounts[u.tool] ?? 0) + 1; });
    const topTools = Object.entries(toolCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([tool, count]) => ({ tool, count }));

    return {
      totalKeys:    allKeys.length,
      activeKeys:   activeKeys.length,
      callsToday,
      callsMonth,
      mrrUsd:       mrr,
      tierBreakdown,
      topTools,
      recentActivity: this.usage.slice(0, 20),
    };
  }
}

const usageTracker = new UsageStore();
export default usageTracker;
export { TIER_CONFIG };
