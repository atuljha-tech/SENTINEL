import ora from 'ora';
import chalk from 'chalk';
import Table from 'cli-table3';
import { api, c, riskColor, levelColor, divider, sectionHeader, verdictBadge } from '../utils';

export async function scanCommand(url: string) {
  const fullUrl = url.startsWith('http') ? url : `https://${url}`;

  console.log();
  console.log(sectionHeader('SANDBOX SCAN', `Target → ${fullUrl}`));
  console.log();

  const spinner = ora({
    text: chalk.hex('#76b900')('Launching isolated Playwright browser...'),
    color: 'green',
    spinner: 'dots2',
  }).start();

  const data = await api('post', '/api/sandbox-scan', { url: fullUrl });
  spinner.succeed(chalk.greenBright('Scan complete'));

  if (!data.success || !data.result) {
    console.error(c.high('\n  ✗ Scan failed'));
    return;
  }

  const r = data.result;
  const col = riskColor(r.riskScore);

  // Verdict banner
  console.log();
  console.log('  ' + verdictBadge(r.sandboxVerdict, r.riskScore));
  console.log();

  // Stats table
  const table = new Table({
    head: [
      chalk.hex('#76b900').bold('Field'),
      chalk.hex('#76b900').bold('Value'),
    ],
    style: { head: [], border: ['gray'] },
    chars: {
      top: '─', 'top-mid': '┬', 'top-left': '╭', 'top-right': '╮',
      bottom: '─', 'bottom-mid': '┴', 'bottom-left': '╰', 'bottom-right': '╯',
      left: '│', 'left-mid': '├', mid: '─', 'mid-mid': '┼',
      right: '│', 'right-mid': '┤', middle: '│',
    },
  });

  table.push(
    [chalk.gray('Domain'),        chalk.white(r.domain)],
    [chalk.gray('Risk Score'),    col(`${r.riskScore} / 100`)],
    [chalk.gray('Security'),      riskColor(100 - r.riskScore)(`${r.securityScore} / 100`)],
    [chalk.gray('Scripts'),       chalk.white(String(r.scriptsCount))],
    [chalk.gray('Cookies'),       chalk.white(String(r.cookiesCount))],
    [chalk.gray('Mixed Content'), chalk.white(String(r.mixedContent))],
  );

  console.log(table.toString());

  // Threats
  if (r.threats && r.threats.length > 0) {
    console.log();
    console.log(chalk.bold.white(`  Detected Issues`) + chalk.gray(` [${r.threats.length}]`));
    console.log('  ' + divider('─', 50));
    r.threats.forEach((t: { level: string; text: string }) => {
      const lc = levelColor(t.level);
      const badge = t.level === 'critical' ? chalk.bgRed.white.bold(` ${t.level.toUpperCase()} `)
                  : t.level === 'high'     ? chalk.bgRedBright.black.bold(` ${t.level.toUpperCase()} `)
                  : t.level === 'medium'   ? chalk.bgYellow.black.bold(` ${t.level.toUpperCase()} `)
                  : chalk.bgCyan.black.bold(` ${t.level.toUpperCase()} `);
      console.log(`  ${badge}  ${chalk.gray(t.text)}`);
    });
  } else {
    console.log();
    console.log(chalk.bgGreen.black.bold(' ✓ NO THREATS ') + chalk.greenBright(' Site appears secure'));
  }

  // Recommendations
  if (r.recommendations && r.recommendations.length > 0) {
    console.log();
    console.log(chalk.bold.white('  AI Recommendations'));
    console.log('  ' + divider('─', 50));
    r.recommendations.slice(0, 3).forEach((rec: string) => {
      console.log(`  ${chalk.hex('#76b900')('›')} ${chalk.gray(rec)}`);
    });
  }

  console.log();
}
