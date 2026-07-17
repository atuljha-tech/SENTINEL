<div align="center">

# SENTINEL
### AI Security Layer for the Agentic Internet

*Real-time threat detection · Sandbox browser isolation · Civic AI Governance · Multi-Agent Orchestration*

[![Next.js](https://img.shields.io/badge/Next.js-16-black?style=flat-square&logo=next.js)](https://nextjs.org)
[![Playwright](https://img.shields.io/badge/Playwright-1.59-45ba4b?style=flat-square&logo=playwright)](https://playwright.dev)
[![Groq](https://img.shields.io/badge/Groq-Llama_3.3_70B-f55036?style=flat-square)](https://groq.com)
[![Civic AI](https://img.shields.io/badge/Civic-AI_Governance-00AA88?style=flat-square)](https://civic.com)
[![Chrome MV3](https://img.shields.io/badge/Chrome-MV3_Extension-4285F4?style=flat-square&logo=googlechrome)](https://developer.chrome.com/docs/extensions/mv3)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=flat-square&logo=typescript)](https://typescriptlang.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

**Built for OKX.AI Genesis Hackathon 2026 · Agent Service Provider**

</div>

---

## Screenshots

<div align="center">

### Landing Page — Live URL Analysis
<img src="public/ss1.png" alt="SENTINEL Landing Page — Live URL Analysis" width="900">
<p><em>Analyze any URL in real-time. Risk score 85/100 · BLOCKED · Critical threats detected instantly.</em></p>

---

### SOC Dashboard — Live Traffic Monitoring
<img src="public/ss2.png" alt="SENTINEL SOC Dashboard" width="900">
<p><em>50 active alerts · 21 attack events · Real-time traffic analysis with risk score overlay and threat distribution chart.</em></p>

---

### Threat Forecast — Predictive AI Engine
<img src="public/ss3.png" alt="SENTINEL Threat Forecast Panel" width="900">
<p><em>95% probability of DDoS attack · 1 minute to peak · AI reasoning from Groq Llama 3.3 70B.</em></p>

---

### Sandbox Scanner — Isolated Playwright Analysis
<img src="public/ss4.png" alt="SENTINEL Sandbox Scanner" width="900">
<p><em>paypal-secure-login.com scanned in isolation · Risk 55/100 · WARNING · Phishing URL pattern detected.</em></p>

</div>

---

## What is SENTINEL?

SENTINEL is a full-stack AI security platform built as an **Agent Service Provider (ASP)** for the OKX.AI ecosystem. Any AI agent can call a single API endpoint to get clearance before navigating to a URL — protecting users from phishing sites, wallet drainers, and malicious scripts.

It monitors live network traffic, scans websites in an **isolated Playwright sandbox** before loading them, uses **Groq's Llama 3.3 70B** to classify threats in real time, and routes every AI decision through **Civic AI's governance layer** for a full audit trail.

### The Problem

AI agents browse the internet blindly. They click links, visit sites, approve transactions — with nothing to warn them. One malicious URL. One wallet drainer. Your users pay the price.

### The Solution

```js
// 5 lines. That's all it takes.
const { clearanceGranted, reason } = await fetch(
  '/api/v1/agent/clearance',
  { method: 'POST', body: JSON.stringify({ url, agentKey }) }
).then(r => r.json());
```

Any OKX.AI agent inherits enterprise-grade security with one API call.

---

## Features

| | Feature | Description | AI Component |
|---|---|---|---|
| 🛡️ | **Live Traffic Monitoring** | Real-time packet logging with AI risk scoring (0–100) | Groq Llama 3.3 |
| 🤖 | **Groq AI Detection** | Llama 3.3 70B classifies DDoS, brute force, port scan, bot traffic | Groq |
| ⚖️ | **Civic AI Governance** | Every AI tool call routed through Civic MCP Hub with hard guardrails | **Civic AI** |
| 🔬 | **Sandbox Scanner** | Playwright headless browser scans sites in isolation before you load them | Groq + Civic |
| 📊 | **Threat Forecast** | Predictive AI engine forecasts attacks before they peak | Groq |
| 🚦 | **Navigation Interceptor** | Chrome extension redirects every navigation through the warning page | - |
| 🖥️ | **Interactive Sandbox Browser** | Browse suspicious sites inside an isolated Chromium stream | - |
| ⚡ | **SSE Live Dashboard** | Server-Sent Events replace polling — instant push updates | - |
| 🔒 | **Auto-Response Engine** | IP blocking, rate limiting — all governed and reversible | **Civic AI** |
| 💻 | **SENTINEL CLI** | Terminal interface — scan, block, monitor without touching the browser | Civic-governed |
| 📤 | **Data Export** | JSON and CSV download of all traffic and threat data | - |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CHROME EXTENSION                        │
│  Navigation Interceptor → Warning Page → Proceed / Block    │
│  Floating Widget · Threat Panel · Real Traffic Logging      │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP / SSE
┌──────────────────────────▼──────────────────────────────────┐
│                   NEXT.JS SERVER :3000                       │
│                                                             │
│  /          SOC Dashboard (8 tabs)                          │
│  /sandbox   Sandbox Scanner + Interactive Browser           │
│  /warning   Navigation Interceptor Warning Page             │
│                                                             │
│  /api/sandbox-scan      Playwright headless scan            │
│  /api/live-updates      SSE stream                          │
│  /api/groq-analyze      Llama 3.3 70B analysis              │
│  /api/civic-audit       Civic MCP tool calls + audit log    │
│  /api/threat-forecast   Predictive threat engine            │
│  /api/v1/agent/clearance  Agent Service Provider API        │
└──────────┬───────────────────────────────────┬──────────────┘
           │                                   │
┌──────────▼──────────┐           ┌────────────▼────────────┐
│  SANDBOX SERVER     │           │     CIVIC MCP HUB        │
│  WebSocket + Express│           │  🛡️ Hard Guardrails      │
│  Playwright Chromium│           │  📝 Full Audit Trail     │
│  Screenshot stream  │           │  ⚡ Rate Limiting        │
└─────────────────────┘           │  🔑 Permission Control   │
                                  └─────────────────────────┘
```

---

## Stack

| Layer | Tech | AI Component |
|---|---|---|
| Frontend | Next.js 16 · React 19 · TypeScript 5 | - |
| Charts | Recharts 3 with animated area/bar/pie | - |
| AI Inference | Groq SDK · Llama 3.3 70B Versatile | **Groq** |
| AI Governance | Civic MCP Hub · JWT token · Guardrails | **Civic AI** |
| Orchestrator | Groq Llama-3.3-70B multi-agent LLM | **Groq** |
| Sandbox | Playwright 1.59 · Chromium headless | - |
| Real-time | Server-Sent Events (native) | - |
| Extension | Chrome MV3 · webNavigation · webRequest | - |
| CLI | Commander · Chalk · Boxen · cli-table3 | - |
| Data Store | In-memory SessionStore (zero DB) | - |

---

## Quick Start

### 1. Clone & install

```bash
git clone https://github.com/atuljha-tech/SENTINEL.git
cd SENTINEL
npm install
npx playwright install chromium
```

### 2. Environment variables

Create `.env.local`:

```env
# Required
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxx

# Optional — falls back to local execution without these
CIVIC_API_KEY=your_civic_jwt
CIVIC_MCP_URL=https://app.civic.com/hub/mcp?accountId=YOUR_ID&profile=default

# Local dev
NEXT_PUBLIC_BASE_URL=http://localhost:3000
```

### 3. Start the dashboard

```bash
npm run dev
# → http://localhost:3000
```

### 4. Start the interactive sandbox server (optional)

```bash
npm run sandbox
# → ws://localhost:4000
```

### 5. Load the Chrome extension

- Open `chrome://extensions`
- Enable **Developer mode**
- Click **Load unpacked** → select the `extension/` folder

---

## SENTINEL CLI

Terminal access to the entire platform. Server must be running.

```bash
# Scan a website in the Playwright sandbox
npm run lokey -- scan github.com
npm run lokey -- scan http://login-verify-account.com

# Full sandbox execution log
npm run lokey -- sandbox example.com

# Show active threat alerts
npm run lokey -- alerts

# Live traffic stream
npm run lokey -- traffic

# Block an IP address (governed by Civic AI)
npm run lokey -- block-ip 45.33.22.11

# Recent sandbox-scanned sites
npm run lokey -- sites

# Full system security stats
npm run lokey -- stats
```

---

## Agent Clearance API

Any OKX.AI agent can call this endpoint before navigating to a URL:

```bash
POST /api/v1/agent/clearance
{
  "url": "https://uniswap-claim-airdrop.com",
  "agentKey": "optional"
}
```

Response:
```json
{
  "clearanceGranted": false,
  "riskScore": 87,
  "reason": "Wallet drainer script detected",
  "suggestedAction": "ABORT",
  "auditId": "civ-20260117-abc123"
}
```

---

## Civic AI Governance

Every AI action is routed through Civic's MCP Hub before execution.

| Guardrail | Description |
|---|---|
| ✓ No localhost blocking | Cannot block 127.0.0.1, localhost, or 0.0.0.0 |
| ✓ Rate limiting | Max 5 `block_ip` calls per minute |
| ✓ Self-protection | AI cannot revoke its own permissions |
| ✓ Domain allowlist | Cannot block *.gov, *.edu, trusted domains |
| ✓ Full audit trail | Every tool call logged with Civic audit ID |

Graceful fallback — if Civic Hub is unreachable, all features continue working with local rules.

---

## Security Scoring

| Check | Risk Added |
|---|---|
| No HTTPS | +40 |
| Password field on HTTP | +40 |
| Session cookie missing Secure flag | +25 |
| Missing Content-Security-Policy | +10 |
| Missing X-Frame-Options | +8 |
| innerHTML assignment in inline JS | +8 |
| Mixed content (HTTP on HTTPS page) | +15 |
| Phishing URL pattern | +45 |
| Known malicious domain | +60 |
| Groq AI enrichment | up to +15 |

**Verdict thresholds:** safe < 35 · warning 35–59 · block ≥ 60

---

## Dashboard Tabs

| Tab | What it shows |
|---|---|
| GOVERNANCE FEED | Live Civic audit trail · tool calls · guardrail results |
| DASHBOARD | Resource monitor · security score · live traffic charts |
| TRAFFIC LOGS | Full packet table with risk scores and attack types |
| THREAT ANALYSIS | Active alerts with AI-powered response actions |
| RESPONSE ENGINE | Blocked IPs with unblock · full response log |
| WEBSITE SECURITY | Recent sandbox scans · Chrome extension feed |
| THREAT FORECAST | Predictive attack probability · AI reasoning |
| AGENT API | Live clearance API test widget · integration guide |

---

## Project Structure

```
├── app/
│   ├── page.tsx              # Landing + SOC Dashboard
│   ├── sandbox/page.tsx      # Sandbox scanner + interactive browser
│   ├── warning/page.tsx      # Navigation interceptor warning page
│   └── api/                  # 18 API routes
├── components/
│   ├── SOCDashboard.tsx
│   ├── GovernanceFeed.tsx    # ★ Hero tab — Civic audit live feed
│   ├── ThreatForecastPanel.tsx
│   ├── AgentActivityPanel.tsx
│   └── WebsiteSecurityPanel.tsx
├── lib/
│   ├── sandboxScanner.ts     # Playwright scanner engine
│   ├── orchestrator.ts       # Groq multi-agent LLM orchestrator
│   ├── civicClient.ts        # 🛡️ Civic MCP Hub client
│   └── sessionStore.ts       # In-memory data store
├── extension/
│   ├── background.js         # Navigation interceptor + traffic logging
│   ├── content.js            # Floating widget + threat panel
│   └── popup.html/js         # Extension popup
├── cli/
│   ├── lokey.ts              # CLI entry point
│   └── commands/             # scan · sandbox · alerts · traffic · block-ip
└── sandbox-server/
    └── server.ts             # WebSocket screenshot streaming
```

---

## Known Limitations

- In-memory only — all data resets on server restart
- Sandbox scan speed — Playwright takes 2–5s per scan
- Navigation interceptor — redirect happens after navigation commits (MV3 limitation)
- Civic dependency — full governance requires internet connection (graceful fallback available)

---

<div align="center">

Built for OKX.AI Genesis Hackathon 2026 · Powered by Groq · Governed by Civic AI

| Component | Role |
|---|---|
| 🚀 Groq | Fast LLM inference (Llama 3.3 70B) |
| 🛡️ Civic AI | Governance, guardrails, audit trails |
| 🔬 Playwright | Isolated sandbox browsing |
| ⚡ Next.js | Full-stack React framework |

</div>
