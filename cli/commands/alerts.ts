import ora from 'ora';
import chalk from 'chalk';
import Table from 'cli-table3';
import { api, c, riskColor, divider, sectionHeader } from '../utils';

export async function alertsCommand(limit = 20) {
  console.log();
  const spinner = ora({ text: chalk.hex('#76b900')('Fetching active alerts...'), color: 'green', spinner: 'dots2' }).start();
  const data = await api('get', '/api/detect');
  spinner.succeed(chalk.greenBright('Alerts loaded'));

  const alerts: any[] = data.alerts ?? [];

  console.log();
  console.log(sectionHeader('ACTIVE ALERTS', `${alerts.length} threat(s) detected`));
  console.log();

  if (alerts.length === 0) {
    console.log(chalk.bgGreen.black.bold(' ✓ SYSTEM SECURE ') + chalk.greenBright(' No active threats'));
    console.log();
    return;
  }

  const table = new Table({
    head: [
      chalk.hex('#76b900').bold('#'),
      chalk.hex('#76b900').bold('Severity'),
      chalk.hex('#76b900').bold('Attack Type'),
      chalk.hex('#76b900').bold('IP Address'),
      chalk.hex('#76b900').bold('Risk'),
      chalk.hex('#76b900').bold('Reason'),
    ],
    style: { head: [], border: ['gray'] },
    colWidths: [4, 12, 18, 18, 6, 36],
    wordWrap: true,
    chars: {
      top: '─', 'top-mid': '┬', 'top-left': '╭', 'top-right': '╮',
      bottom: '─', 'bottom-mid': '┴', 'bottom-left': '╰', 'bottom-right': '╯',
      left: '│', 'left-mid': '├', mid: '─', 'mid-mid': '┼',
      right: '│', 'right-mid': '┤', middle: '│',
    },
  });

  alerts.slice(0, limit).forEach((a: any, i: number) => {
    const risk = a.riskScore ?? 0;
    const col = riskColor(risk);
    const tag = risk >= 70 ? chalk.bgRed.white.bold(' CRITICAL ')
              : risk >= 50 ? chalk.bgRedBright.black.bold(' HIGH ')
              : risk >= 35 ? chalk.bgYellow.black.bold(' WARNING ')
              : chalk.bgCyan.black.bold(' INFO ');
    const ip = a.trafficData?.ip ?? a.ip ?? 'unknown';
    const reason = (a.reasons?.[0] ?? '—').substring(0, 32);

    table.push([
      chalk.gray(String(i + 1)),
      tag,
      chalk.white(a.attackType ?? 'Unknown'),
      chalk.hex('#76b900')(ip),
      col(String(risk)),
      chalk.gray(reason),
    ]);
  });

  console.log(table.toString());

  // Stats breakdown
  if (data.stats) {
    const s = data.stats;
    console.log();
    console.log(chalk.bold.white('  Breakdown'));
    console.log('  ' + divider('─', 30));
    if (s.Attack)     console.log(`  ${chalk.bgRed.white.bold(' ATTACK ')}      ${chalk.redBright(String(s.Attack))}`);
    if (s.Suspicious) console.log(`  ${chalk.bgYellow.black.bold(' SUSPICIOUS ')} ${chalk.yellow(String(s.Suspicious))}`);
    if (s.Normal)     console.log(`  ${chalk.bgGreen.black.bold(' NORMAL ')}     ${chalk.greenBright(String(s.Normal))}`);
  }

  console.log();
}
