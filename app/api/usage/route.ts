// ============================================================
// SENTINEL USAGE & REVENUE METRICS API
// GET  /api/usage         — overall metrics dashboard
// GET  /api/usage?key=xxx — usage for a specific key
// POST /api/usage/keys    — create a new API key
// ============================================================

import { NextRequest, NextResponse } from 'next/server';
import usageTracker, { TIER_CONFIG, Tier } from '@/lib/usageTracker';

export async function GET(req: NextRequest) {
  const key = req.nextUrl.searchParams.get('key');

  if (key) {
    const keyData = usageTracker.validateKey(key);
    if (!keyData) {
      return NextResponse.json({ success: false, error: 'Invalid API key' }, { status: 404 });
    }
    const usage    = usageTracker.getUsageForKey(key);
    const limits   = TIER_CONFIG[keyData.tier];
    const limitCheck = usageTracker.checkLimit(key);

    return NextResponse.json({
      success: true,
      key:     keyData,
      limits,
      usage: {
        records:   usage.slice(0, 50),
        total:     usage.length,
        remaining: limitCheck.remaining,
      },
    });
  }

  const metrics = usageTracker.getMetrics();
  const allKeys = usageTracker.getAllKeys();

  return NextResponse.json({
    success: true,
    metrics,
    keys:    allKeys,
    tiers:   TIER_CONFIG,
  });
}

export async function POST(req: NextRequest) {
  try {
    const { agentId, tier = 'free', label = 'New Key' } = await req.json();
    if (!agentId) {
      return NextResponse.json({ success: false, error: 'agentId required' }, { status: 400 });
    }

    const key = usageTracker.createKey(agentId, tier as Tier, label);
    return NextResponse.json({ success: true, key }, { status: 201 });
  } catch (err) {
    return NextResponse.json({ success: false, error: 'Failed to create key' }, { status: 500 });
  }
}
