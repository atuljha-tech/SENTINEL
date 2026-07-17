// ============================================================
// SENTINEL THREAT REGISTRY API
// GET  /api/registry?url=xxx      — check a URL/IP
// GET  /api/registry?action=all   — get all entries
// GET  /api/registry?action=stats — get stats
// POST /api/registry              — report a new threat
// ============================================================

import { NextRequest, NextResponse } from 'next/server';
import threatRegistry, { ThreatCategory } from '@/lib/threatRegistry';

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: CORS });
}

export async function GET(req: NextRequest) {
  const { searchParams } = req.nextUrl;
  const url    = searchParams.get('url') ?? searchParams.get('ip') ?? searchParams.get('domain');
  const action = searchParams.get('action');

  if (action === 'stats') {
    return NextResponse.json({ success: true, stats: threatRegistry.getStats() }, { headers: CORS });
  }

  if (action === 'all' || action === 'list') {
    const limit = parseInt(searchParams.get('limit') ?? '50');
    return NextResponse.json(
      { success: true, entries: threatRegistry.getAll(limit), count: threatRegistry.getAll(limit).length },
      { headers: CORS }
    );
  }

  if (url) {
    const entry = threatRegistry.check(url);
    return NextResponse.json(
      {
        success: true,
        found:   !!entry,
        threat:  entry ?? null,
        message: entry
          ? `⚠ Threat found: ${entry.category} (score: ${entry.riskScore})`
          : '✓ No threats found in registry',
      },
      { headers: CORS }
    );
  }

  return NextResponse.json(
    { success: true, stats: threatRegistry.getStats(), topThreats: threatRegistry.getAll(10) },
    { headers: CORS }
  );
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const {
      type        = 'url',
      value,
      category    = 'unknown' as ThreatCategory,
      riskScore   = 70,
      reportedBy  = 'community',
      description = 'Reported by community',
      tags        = [],
    } = body;

    if (!value) {
      return NextResponse.json(
        { success: false, error: 'value (url/ip/domain) is required' },
        { status: 400, headers: CORS }
      );
    }

    const entry = threatRegistry.report({ type, value, category, riskScore, reportedBy, description, tags });

    return NextResponse.json(
      {
        success: true,
        message: `Threat reported. Total reports for this indicator: ${entry.reportCount}`,
        entry,
      },
      { status: 201, headers: CORS }
    );
  } catch (err) {
    console.error('[Registry] POST error:', err);
    return NextResponse.json(
      { success: false, error: 'Failed to record threat report' },
      { status: 500, headers: CORS }
    );
  }
}
