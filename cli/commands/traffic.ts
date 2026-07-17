import ora from 'ora';
import chalk from 'chalk';
import { api, c, riskColor, sectionHeader } from '../utils';

export async function trafficCommand(limit = 30) {
  console.log();
  const spinner = ora({ text: chalk.hex('#76b900')('Fetching live traffic...'), color: 'green', spinner: 'dots2' }).start();
  const data = await api('get', '/api/traffic');
  spinner.succeed(chalk.greenBright('Traffic loaded'));

  const logs: any[] = data.data ?? [];

  console.log();
  console.log(sectionHeader('LIVE TRAFFIC STREAM', `${logs.length} packet(s) logged`));
  console.log();

  if (logs.length === 0) {
    console.log(chalk.gray('  // awaiting traffic data...'));
    console.log();
    return;
  }

  logs.slice(0, limit).forEach((t: any) => {
    const risk = t.riskScore ?? 0;
    const col = riskColor(risk);
    const time = t.timestamp
      ? new Date(t.timestamp).toLocaleTimeString('en-US', { hour12: false })
      : '--:--:--';

    const statusBadge = t.threatStatus === 'Attack'
      ? chalk.bgRed.white.bold(' ATTACK ')
      : t.threatStatus === 'Suspicious'
        ? chalk.bgYellow.black.bold(' SUSPICIOUS ')
        : chalk.bgGreen.black.bold(' SAFE ');

    const riskBadge = risk > 0 ? col(` RISK:${risk} `) : '';
    const attackBadge = (t.attackType && t.attackType !== 'None')
      ? chalk.magentaBright(` ${t.attackType}`)
      : '';

    console.log(
      `  ${chalk.gray(`[${time}]`)}  ` +
      `${chalk.hex('#76b900')((t.ip ?? 'unknown').padEnd(16))}` +
      `${chalk.gray(`:${String(t.port ?? 0).padEnd(6)}`)}` +
      `${chalk.gray((t.protocol ?? 'TCP').padEnd(6))}` +
      `${statusBadge}` +
      `${riskBadge}` +
      `${attackBadge}`
    );
  });

  console.log();
}
