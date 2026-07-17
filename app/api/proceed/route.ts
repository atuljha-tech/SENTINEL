import { NextRequest, NextResponse } from 'next/server';

// Tracks URLs the user has explicitly allowed — extension reads this
// to skip the warning page on the next navigation to that URL.
const allowedUrls = new Set<string>();

export async function GET(req: NextRequest) {
  const url = req.nextUrl.searchParams.get('url');
  if (!url) {
    return NextResponse.json({ error: 'url required' }, { status: 400 });
  }

  // Mark this URL as allowed for 60 seconds
  allowedUrls.add(url);
  setTimeout(() => allowedUrls.delete(url), 60_000);

  // Redirect the browser directly to the real destination
  return NextResponse.redirect(url, { status: 302 });
}

export async function POST(req: NextRequest) {
  const { url } = await req.json().catch(() => ({ url: null }));
  if (!url) return NextResponse.json({ error: 'url required' }, { status: 400 });
  allowedUrls.add(url);
  setTimeout(() => allowedUrls.delete(url), 60_000);
  return NextResponse.json({ allowed: true });
}

export function isAllowed(url: string): boolean {
  return allowedUrls.has(url);
}
