import ora from 'ora';
import chalk from 'chalk';
import Table from 'cli-table3';
import { api, riskColor, sectionHeader } from '../utils';

export async function sitesCommand() {
  console.log();
  const spinner = ora({ text: chalk.hex('#76b900')('Fetching recent sandbox scans...'), color: 'green', spinner: 'dots2' }).start();
  const data = await api('get', '/api/sandbox-scan');
  spinner.succeed(chalk.greenBright('Sites loaded'));

  const sites: any[] = data.recentSites ?? [];

  console.log();
  console.log(sectionHeader('RECENT SANDBOX SCANS', `${sites.length} site(s) scanned`));
  console.log();

  if (sites.length === 0) {
    console.log(chalk.gray('  // no sandbox scans yet'));
    console.log(chalk.gray('  // run: lokey scan <url>'));
    console.log();
    return;
  }

  const table = new Table({
    head: [
      chalk.hex('#76b900').bold('Domain'),
      chalk.hex('#76b900').bold('Verdict'),
      chalk.hex('#76b900').bold('Score'),
      chalk.hex('#76b900').bold('Risk'),
      chalk.hex('#76b900').bold('Scanned At'),
    ],
    style: { head: [], border: ['gray'] },
    colWidths: [32, 12, 8, 8, 12],
    chars: {
      top: '─', 'top-mid': '┬', 'top-left': '╭', 'top-right': '╮',
      bottom: '─', 'bottom-mid': '┴', 'bottom-left': '╰', 'bottom-right': '╯',
      left: '│', 'left-mid': '├', mid: '─', 'mid-mid': '┼',
      right: '│', 'right-mid': '┤', middle: '│',
    },
  });

  sites.forEach((s: any) => {
    const col = riskColor(s.riskScore);
    const v = s.sandboxVerdict?.toUpperCase() ?? 'UNKNOWN';
    const verdictCell = v === 'BLOCK'   ? chalk.bgRed.white.bold(' BLOCK ')
                      : v === 'WARNING' ? chalk.bgYellow.black.bold(' WARN ')
                      : chalk.bgGreen.black.bold(' SAFE ');
    const time = s.timestamp
      ? new Date(s.timestamp).toLocaleTimeString('en-US', { hour12: false })
      : '--:--:--';

    table.push([
      chalk.hex('#76b900')(s.domain ?? s.url ?? 'unknown'),
      verdictCell,
      riskColor(100 - s.riskScore)(String(s.securityScore ?? 0)),
      col(String(s.riskScore ?? 0)),
      chalk.gray(time),
    ]);
  });

  console.log(table.toString());
  console.log();
}
