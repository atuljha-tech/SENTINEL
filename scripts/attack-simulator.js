#!/usr/bin/env node
// ============================================
// AI-NMS Real Attack Simulator
// Generates realistic attack traffic for demo
// Usage: node scripts/attack-simulator.js
// ============================================

const path = require('path');
const fs = require('fs');

// Load .env.local
const envPath = path.resolve(__dirname, '../.env.local');
if (fs.existsSync(envPath)) {
  const lines = fs.readFileSync(envPath, 'utf8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      const [key, ...val] = trimmed.split('=');
      if (key && val.length) process.env[key] = val.join('=');
    }
  }
}

const BASE_URL = process.env.NEXT_PUBLIC_URL || 'http://localhost:3000';

const colors = {
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  blue: '\x1b[34m', purple: '\x1b[35m', cyan: '\x1b[36m', reset: '\x1b[0m'
};

const log = (color, msg) => console.log(`${colors[color]}${msg}${colors.reset}`);

// Attack scenarios
const ATTACKS = [
  {
    name: 'DDoS Attack',
    icon: '💥',
    packets: 15,
    generator: () => ({
      ip: `${randomInt(1,254)}.${randomInt(1,254)}.${randomInt(1,254)}.${randomInt(1,254)}`,
      port: [80, 443, 8080][randomInt(0,2)],
      protocol: 'TCP',
      requestCount: randomInt(100, 300),
      source: 'ddos-simulator'
    })
  },
  {
    name: 'Brute Force SSH',
    icon: '🔨',
    packets: 10,
    generator: () => ({
      ip: `185.${randomInt(1,254)}.${randomInt(1,254)}.${randomInt(1,254)}`,
      port: 22,
      protocol: 'TCP',
      requestCount: randomInt(50, 120),
      source: 'bruteforce-simulator'
    })
  },
  {
    name: 'Port Scan',
    icon: '🔍',
    packets: 8,
    generator: (i) => ({
      ip: '45.33.22.11',
      port: [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5900][i % 10],
      protocol: 'TCP',
      requestCount: randomInt(1, 10),
      source: 'portscan-simulator'
    })
  },
  {
    name: 'Bot Traffic',
    icon: '🤖',
    packets: 12,
    generator: () => ({
      ip: `103.${randomInt(1,254)}.${randomInt(1,254)}.${randomInt(1,254)}`,
      port: 443,
      protocol: 'HTTPS',
      requestCount: randomInt(30, 80),
      source: 'bot-simulator'
    })
  },
  {
    name: 'Known Malicious IPs',
    icon: '☠️',
    packets: 5,
    generator: () => ({
      ip: ['45.33.22.11','185.130.5.253','94.102.61.78','193.42.56.78','5.188.86.45'][randomInt(0,4)],
      port: [22, 3389, 445][randomInt(0,2)],
      protocol: 'TCP',
      requestCount: randomInt(20, 60),
      source: 'malicious-ip-simulator'
    })
  }
];

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

async function sendTraffic(data) {
  const res = await fetch(`${BASE_URL}/api/traffic`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return res.json();
}

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function runSimulation() {
  console.log(`
${colors.cyan}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     🎯 AI-NMS Attack Simulator                              ║
║                                                              ║
║     Generating realistic attack traffic...                  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝${colors.reset}
`);

  log('blue', `📡 Target: ${BASE_URL}`);
  console.log('');

  let totalSent = 0;

  for (const attack of ATTACKS) {
    log('yellow', `${attack.icon} Simulating: ${attack.name}`);

    for (let i = 0; i < attack.packets; i++) {
      try {
        const data = attack.generator(i);
        await sendTraffic(data);
        process.stdout.write(`${colors.green}.${colors.reset}`);
        totalSent++;
        await sleep(100);
      } catch (err) {
        process.stdout.write(`${colors.red}x${colors.reset}`);
      }
    }

    console.log(` ${colors.green}✓ ${attack.packets} packets sent${colors.reset}`);
    await sleep(500);
  }

  console.log('');
  log('green', `═══════════════════════════════════════════════════════════════`);
  log('green', `  ✅ SIMULATION COMPLETE! ${totalSent} attack packets sent`);
  log('green', `═══════════════════════════════════════════════════════════════`);
  console.log('');
  log('cyan', `📊 Now go to your dashboard and click "🧠 Run AI Detection"`);
  log('cyan', `   to analyze the simulated attacks!`);
  console.log('');
}

runSimulation().catch(err => {
  log('red', `❌ Error: ${err.message}`);
  log('yellow', `💡 Make sure your Next.js server is running: npm run dev`);
  process.exit(1);
});
