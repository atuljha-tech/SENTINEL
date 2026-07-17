import ora from 'ora';
import chalk from 'chalk';
import Table from 'cli-table3';
import boxen from 'boxen';
import { api, c, divider, sectionHeader } from '../utils';

export async function blockIpCommand(ip: string) {
  console.log();
  console.log(sectionHeader('AI RESPONSE ENGINE', `Target → ${ip}`));
  console.log();

  const spinner = ora({
    text: chalk.hex('#76b900')('Routing through Civic guardrails...'),
    color: 'green',
    spinner: 'dots2',
  }).start();

  const data = await api('post', '/api/respond', {
    ip,
    attackType: 'Manual Block',
    riskScore: 100,
    threatStatus: 'Attack',
    autoExecute: true,
  });

  spinner.stop();

  const d = data.decision ?? {};
  const civic = data.civic ?? {};

  // Decision table
  const table = new Table({
    style: { head: [], border: ['gray'] },
    chars: {
      top: '─', 'top-mid': '┬', 'top-left': '╭', 'top-right': '╮',
      bottom: '─', 'bottom-mid': '┴', 'bottom-left': '╰', 'bottom-right': '╯',
      left: '│', 'left-mid': '├', mid: '─', 'mid-mid': '┼',
      right: '│', 'right-mid': '┤', middle: '│',
    },
  });

  table.push(
    [chalk.gray('Decision'),      chalk.white(d.action ?? 'UNKNOWN')],
    [chalk.gray('Target IP'),     chalk.hex('#76b900')(ip)],
    [chalk.gray('Reason'),        chalk.gray(d.reason ?? '—')],
    [chalk.gray('Severity'),      chalk.white(d.severity ?? '—')],
    [chalk.gray('Auto Executed'), d.autoExecuted ? chalk.greenBright('✓ YES') : chalk.yellow('✗ NO')],
  );

  console.log(table.toString());

  // Civic panel
  const civicStatus = civic.guardrailPassed
    ? chalk.bgGreen.black.bold(' ✓ PASSED ')
    : chalk.bgRed.white.bold(' ✗ BLOCKED ');

  console.log(
    boxen(
      `${chalk.hex('#76b900').bold('Civic Governance')}\n\n` +
      `  Guardrails   ${civicStatus}\n` +
      `  Tool         ${chalk.gray(civic.tool ?? '—')}\n` +
      `  Audit ID     ${chalk.gray(civic.auditId ? civic.auditId.substring(0, 20) + '...' : '—')}`,
      {
        padding: { top: 0, bottom: 0, left: 1, right: 1 },
        borderStyle: 'round',
        borderColor: civic.guardrailPassed ? 'green' : 'red',
      }
    )
  );

  console.log();

  if (data.success && d.autoExecuted) {
    console.log(chalk.bgGreen.black.bold(` ✓ ${ip} has been blocked `));
  } else if (!civic.guardrailPassed) {
    console.log(chalk.bgRed.white.bold(` ✗ Blocked by Civic guardrail `) + chalk.gray(` ${civic.reason}`));
  } else {
    console.log(chalk.bgYellow.black.bold(' ⚠ Action logged but not auto-executed '));
  }

  if (data.recommendations?.length > 0) {
    console.log();
    console.log(chalk.bold.white('  Recommendations'));
    console.log('  ' + divider('─', 40));
    data.recommendations.slice(0, 2).forEach((r: string) => {
      console.log(`  ${chalk.hex('#76b900')('›')} ${chalk.gray(r)}`);
    });
  }

  console.log();
}
