import ora from 'ora';
import chalk from 'chalk';
import { api, c, riskColor, levelColor, divider, sectionHeader, verdictBadge } from '../utils';

const STEPS = [
  'Initializing isolated Chromium context...',
  'Launching Playwright browser...',
  'Opening URL — no cookies, no history...',
  'Collecting HTTP response headers...',
  'Enumerating loaded scripts...',
  'Reading cookie metadata...',
  'Scanning inline JS for dangerous patterns...',
  'Checking for mixed content...',
  'Running phishing URL pattern analysis...',
  'Cross-referencing malicious domain list...',
  'Computing final risk score...',
];

const STEP_ICONS = ['⬡','⬡','⬡','⬡','⬡','⬡','⬡','⬡','⬡','⬡','⬡'];

export async function sandboxCommand(url: string) {
  const fullUrl = url.startsWith('http') ? url : `https://${url}`;

  console.log();
  console.log(sectionHeader('SANDBOX EXECUTION LOG', `Target → ${fullUrl}`));
  console.log();

  let stepIdx = 0;
  const stepInterval = setInterval(() => {
    if (stepIdx < STEPS.length) {
      const icon = chalk.hex('#76b900')('›');
      console.log(`  ${chalk.gray('SANDBOX')} ${icon} ${chalk.gray(STEPS[stepIdx])}`);
      stepIdx++;
    }
  }, 350);

  const data = await api('post', '/api/sandbox-scan', { url: fullUrl });
  clearInterval(stepInterval);

  while (stepIdx < STEPS.length) {
    const icon = chalk.hex('#76b900')('›');
    console.log(`  ${chalk.gray('SANDBOX')} ${icon} ${chalk.gray(STEPS[stepIdx])}`);
    stepIdx++;
  }

  if (!data.success || !data.result) {
    console.error(c.high('\n  SANDBOX › error: scan failed'));
    return;
  }

  const r = data.result;
  const col = riskColor(r.riskScore);

  console.log();
  console.log('  ' + chalk.gray('─'.repeat(52)));

  const rows = [
    ['scripts_found',       chalk.white(String(r.scriptsCount))],
    ['cookies_found',       chalk.white(String(r.cookiesCount))],
    ['mixed_content',       chalk.white(String(r.mixedContent))],
    ['suspicious_patterns', chalk.white(String(r.suspiciousPatterns?.length ?? 0))],
    ['risk_score',          col(`${r.riskScore} / 100`)],
    ['security_score',      chalk.white(`${r.securityScore} / 100`)],
    ['threats_found',       chalk.white(String(r.threats?.length ?? 0))],
  ];

  rows.forEach(([k, v]) => {
    console.log(`  ${chalk.gray('SANDBOX')} ${chalk.hex('#76b900')('›')} ${chalk.gray((k as string).padEnd(22))} ${v}`);
  });

  console.log('  ' + chalk.gray('─'.repeat(52)));
  console.log();
  console.log('  ' + verdictBadge(r.sandboxVerdict, r.riskScore));

  if (r.threats && r.threats.length > 0) {
    console.log();
    console.log(chalk.bold.white('  Findings') + chalk.gray(` [${r.threats.length}]`));
    console.log('  ' + divider('─', 50));
    r.threats.forEach((t: { level: string; text: string }) => {
      const badge = t.level === 'critical' ? chalk.bgRed.white.bold(` ${t.level.toUpperCase()} `)
                  : t.level === 'high'     ? chalk.bgRedBright.black.bold(` ${t.level.toUpperCase()} `)
                  : t.level === 'medium'   ? chalk.bgYellow.black.bold(` ${t.level.toUpperCase()} `)
                  : chalk.bgCyan.black.bold(` ${t.level.toUpperCase()} `);
      console.log(`  ${badge}  ${chalk.gray(t.text)}`);
    });
  }

  console.log();
}
