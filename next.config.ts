import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Required for Playwright to be importable without crashing on Vercel
  // (it will fall back to lightweightScan automatically)
  serverExternalPackages: ['playwright', 'playwright-core'],

  // Allow the sandbox server origin in production
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          { key: 'Access-Control-Allow-Origin', value: '*' },
          { key: 'Access-Control-Allow-Methods', value: 'GET,POST,OPTIONS' },
          { key: 'Access-Control-Allow-Headers', value: 'Content-Type' },
        ],
      },
    ];
  },
};

export default nextConfig;
