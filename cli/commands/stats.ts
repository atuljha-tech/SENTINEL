import ora from 'ora';
import chalk from 'chalk';
import Table from 'cli-table3';
import boxen from 'boxen';
import { api, riskColor, sectionHeader, divider } from '../utils';

export async function statsCommand() {
  console.log();
  const spinner = ora({ text: chalk.hex('#76b900')('Connecting to AI engine...'), color: 'green', spinner: 'dots2' }).start();

  const [trafficData, detectData, respondData, sandboxData] = await Promise.all([
    api('get', '/api/traffic'),
    api('get', '/api/detect'),
    api('get', '/api/respond'),
    api('get', '/api/sandbox-scan'),
  ]);

  spinner.succeed(chalk.greenBright('System data loaded'));

  const traffic: any[] = trafficData.data ?? [];
  const alerts: any[]  = detectData.alerts ?? [];
  const blocked: any[] = respondData.blockedIPs ?? [];
  const sites: any[]   = sandboxData.recentSites ?? [];

  const totalSafe    = traffic.filter((t: any) => (t.riskScore ?? 0) < 35).length;
  const totalSuspect = traffic.filter((t: any) => (t.riskScore ?? 0) >= 35 && (t.riskScore ?? 0) < 70).length;
  const totalAttack  = traffic.filter((t: any) => (t.riskScore ?? 0) >= 70).length;
  const secScore     = traffic.length > 0 ? Math.round((totalSafe / traffic.length) * 100) : 100;

  const threatLevel = totalAttack > 10 ? 'CRITICAL'
                    : totalAttack > 5  ? 'HIGH'
                    : totalAttack > 0  ? 'MEDIUM'
                    : alerts.length > 0 ? 'LOW'
                    : 'SAFE';

  const threatBadge = threatLevel === 'CRITICAL' ? chalk.bgRed.white.bold(` ${threatLevel} `)
                    : threatLevel === 'HIGH'      ? chalk.bgRedBright.black.bold(` ${threatLevel} `)
                    : threatLevel === 'MEDIUM'    ? chalk.bgYellow.black.bold(` ${threatLevel} `)
                    : threatLevel === 'LOW'       ? chalk.bgCyan.black.bold(` ${threatLevel} `)
                    : chalk.bgGreen.black.bold(` ${threatLevel} `);

  const scoreCol = riskColor(100 - secScore);

  console.log();
  console.log(sectionHeader('SYSTEM SECURITY STATUS'));
  console.log();

  // Overview box
  console.log(
    boxen(
      `  ${chalk.hex('#76b900').bold('Security Score')}   ${scoreCol(`${secScore} / 100`)}\n` +
      `  ${chalk.hex('#76b900').bold('Threat Level')}     ${threatBadge}`,
      {
        padding: { top: 0, bottom: 0, left: 1, right: 2 },
        borderStyle: 'round',
        borderColor: secScore >= 70 ? 'green' : secScore >= 40 ? 'yellow' : 'red',
      }
    )
  );

  console.log();

  // Traffic breakdown table
  const trafficTable = new Table({
    head: [chalk.hex('#76b900').bold('Category'), chalk.hex('#76b900').bold('Count'), chalk.hex('#76b900').bold('Bar')],
    style: { head: [], border: ['gray'] },
    colWidths: [16, 10, 30],
    chars: {
      top: '─', 'top-mid': '┬', 'top-left': '╭', 'top-right': '╮',
      bottom: '─', 'bottom-mid': '┴', 'bottom-left': '╰', 'bottom-right': '╯',
      left: '│', 'left-mid': '├', mid: '─', 'mid-mid': '┼',
      right: '│', 'right-mid': '┤', middle: '│',
    },
  });

  const total = traffic.length || 1;
  const bar = (n: number, color: (s: string) => string) => {
    const len = Math.round((n / total) * 24);
    return color('█'.repeat(len)) + chalk.gray('░'.repeat(24 - len));
  };

  trafficTable.push(
    [chalk.greenBright('Safe'),       chalk.greenBright(String(totalSafe)),    bar(totalSafe, chalk.greenBright)],
    [chalk.yellow('Suspicious'),      chalk.yellow(String(totalSuspect)),       bar(totalSuspect, chalk.yellow)],
    [chalk.redBright('Attack'),       chalk.redBright(String(totalAttack)),     bar(totalAttack, chalk.redBright)],
    [chalk.white('Total'),            chalk.white(String(traffic.length)),      chalk.gray('─'.repeat(24))],
  );

  console.log(trafficTable.toString());

  // Summary stats
  const statsTable = new Table({
    style: { head: [], border: ['gray'] },
    chars: {
      top: '─', 'top-mid': '┬', 'top-left': '╭', 'top-right': '╮',
      bottom: '─', 'bottom-mid': '┴', 'bottom-left': '╰', 'bottom-right': '╯',
      left: '│', 'left-mid': '├', mid: '─', 'mid-mid': '┼',
      right: '│', 'right-mid': '┤', middle: '│',
    },
  });

  statsTable.push(
    [chalk.gray('Active Alerts'),  alerts.length > 0  ? chalk.redBright(String(alerts.length))  : chalk.greenBright('0')],
    [chalk.gray('Blocked IPs'),    blocked.length > 0 ? chalk.yellow(String(blocked.length))    : chalk.white('0')],
    [chalk.gray('Sites Scanned'),  chalk.white(String(sites.length))],
  );

  console.log(statsTable.toString());

  // Blocked IPs
  if (blocked.length > 0) {
    console.log();
    console.log(chalk.bold.white('  Blocked IPs'));
    console.log('  ' + divider('─', 44));
    blocked.slice(0, 5).forEach((b: any) => {
      console.log(
        `  ${chalk.bgRed.white(' BLOCKED ')} ${chalk.hex('#76b900')(b.ip.padEnd(18))} ` +
        chalk.gray((b.reason ?? '').substring(0, 36))
      );
    });
  }

  // Top threats
  if (alerts.length > 0) {
    console.log();
    console.log(chalk.bold.white('  Top Threats'));
    console.log('  ' + divider('─', 44));
    alerts.slice(0, 3).forEach((a: any) => {
      const ip = a.trafficData?.ip ?? a.ip ?? 'unknown';
      const risk = a.riskScore ?? 0;
      const col = riskColor(risk);
      console.log(
        `  ${chalk.magentaBright((a.attackType ?? 'Unknown').padEnd(18))} ` +
        `${chalk.hex('#76b900')(ip.padEnd(18))} ` +
        `${col(`risk:${risk}`)}`
      );
    });
  }

  console.log();
}
