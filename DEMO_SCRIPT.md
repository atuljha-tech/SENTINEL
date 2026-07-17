# SENTINEL — OKX.AI Genesis Hackathon Demo Script
## 90-Second Demo Narrative

---

### [0:00 - 0:10] THE HOOK
**Screen:** Show a split: left = news headline "AI trading agent drained of $2.3M after approving malicious contract" / right = simple code block:
```js
await agent.navigate(untrustedUrl)  // no protection
await agent.approveTransaction()     // compromised
```
**Voiceover:**
> "AI agents are operating on the internet with zero security awareness. They click links, visit sites, approve transactions — with nothing to warn them. One malicious URL. One wallet drainer. Your users pay the price."

---

### [0:10 - 0:25] THE PROBLEM MADE REAL
**Screen:** Navigate to SENTINEL landing page at `https://sentinel.vercel.app`
**Voiceover:**
> "This is SENTINEL. The AI security layer every agent needs. Watch what happens when we give it a suspicious DeFi URL."

**Action:** Type `https://uniswap-claim-airdrop.com` into the hero input. Hit ANALYZE.

---

### [0:25 - 0:55] THE RESOLUTION (Live Demo)
**Screen:** The warning page loads. Left side: Playwright execution log streaming in real time. Right side: risk score building from 0 → 87.

Watch the log stream:
```
SANDBOX> intercepting navigation request...
SANDBOX> launching isolated Playwright browser...
SANDBOX> scanning inline JS for dangerous patterns...
SANDBOX> risk_score: 87 / 100
SANDBOX> VERDICT: BLOCK — wallet drainer detected
```

**Voiceover:**
> "SENTINEL analyzed that in 8 seconds in a completely isolated environment. Your agent never touched it."

**Screen:** Cut to SOC Dashboard → Governance Live Feed tab.
Show the auto-generated governance entry:
```
ThreatScoutAgent → log_security_event → guardrail ✓ → EXECUTED
IP: — | Risk: 87/100 | wallet drainer script detected
Civic Hub: ✓ | Audit ID: civ-20260117-abc...
```

**Voiceover:**
> "Every automated decision is logged to an immutable Civic governance audit trail. Full transparency, human-reviewable at any time."

---

### [0:55 - 1:10] THE ASP VALUE — The Money Shot
**Screen:** Show the Agent API tab. Live test widget visible.

**Voiceover:**
> "But SENTINEL isn't just a dashboard. It's an Agent Service Provider. Any OKX.AI agent can call our clearance API."

**Action:** Run the live API test with `https://uniswap-claim-airdrop.com`.

**Screen shows:**
```json
{
  "clearanceGranted": false,
  "riskScore": 87,
  "reason": "Wallet drainer script detected",
  "suggestedAction": "ABORT",
  "auditId": "civ-20260117-abc123"
}
```

**Screen:** Show the code example:
```js
// 5 lines. That's all it takes.
const { clearanceGranted, reason } = await fetch(
  '/api/v1/agent/clearance',
  { method: 'POST', body: JSON.stringify({ url, agentKey }) }
).then(r => r.json());
```

**Voiceover:**
> "Five lines of code. Any agent inherits enterprise-grade security."

---

### [1:10 - 1:30] THE SCALE STORY
**Screen:** Threat Forecast panel showing probability gauge and time-series chart.

**Voiceover:**
> "SENTINEL doesn't just react. It predicts. Based on traffic patterns, it forecasts attacks before they peak — giving your agents time to act."

**Screen:** Switch to Dashboard → Attack Simulator. Trigger a DDoS simulation.

Watch governance feed auto-populate with orchestrator decisions:
- ThreatScoutAgent detects pattern
- LLM Orchestrator selects: rate_limit → civic_log
- Civic governance records audit trail

**Voiceover:**
> "Multi-agent. Governed. Auditable. The security layer the agentic internet has been missing."

**Final screen:** Landing page with the hero text + OKX.AI badge.
> "SENTINEL. Built for OKX.AI Genesis. Available as an ASP today."

---

## X POST VARIATIONS

### 1. Professional
```
We built SENTINEL for the #OKXAI Genesis Hackathon.

The problem: AI agents browse the web blindly — no way to detect phishing, wallet drainers, or malicious scripts before it's too late.

Our answer: a multi-agent security layer any agent can call. One API. Sandbox isolation. Civic governance audit trail.

Built on @groq + Playwright + @CivicKey

Demo: [link]
```

### 2. Hype
```
your AI agent just approved a wallet drainer

not because it was dumb
because nothing warned it

SENTINEL fixes that

5 lines of code
sandbox isolation
civic audit trail

we're coming for that $100K 🔒

#OKXAI genesis
demo → [link]
```

### 3. Community
```
builders in #OKXAI Genesis — how are you handling security for your agents?

we kept asking the same question and decided to build the answer

SENTINEL: multi-agent security ASP
→ sandbox any URL before your agent touches it
→ civic governance audit trail on every decision
→ predictive threat forecasting
→ open API, free tier

if you're building an OKX.AI agent and want "your agent is safe" in your pitch, we should talk

#OKXAI [link]
```

---

## DEMO CHECKLIST

Before recording:
- [ ] `npm run dev` running on localhost:3000
- [ ] GROQ_API_KEY set in .env.local
- [ ] Open Chrome with SENTINEL extension installed
- [ ] Dashboard showing some simulated traffic (auto-starts)
- [ ] Governance tab pre-populated (visit civic tab briefly)
- [ ] Threat Forecast shows data (GET /api/threat-forecast working)

Key URLs to demo:
- ✅ Safe: `https://github.com`
- ⚠ Warning: `https://example.com` (minor issues)
- ⛔ Block: `http://login-verify-account.com`
- ⛔ Block: `https://uniswap-claim-airdrop.com` (wallet drainer)
