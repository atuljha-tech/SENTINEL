// Central config — single source of truth for the base URL
// Server-side: uses NEXT_PUBLIC_BASE_URL env var
// Client-side: same env var (NEXT_PUBLIC_ prefix makes it available in browser)

export const BASE_URL =
  process.env.NEXT_PUBLIC_BASE_URL ||
  (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : 'http://localhost:3000');
