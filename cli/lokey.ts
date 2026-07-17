#!/usr/bin/env ts-node
import { Command } from 'commander';
import chalk from 'chalk';
import figlet from 'figlet';
import boxen from 'boxen';
// @ts-ignore
import gradient from 'gradient-string';

import { scanCommand }    from './commands/scan';
import { sandboxCommand } from './commands/sandbox';
import { alertsCommand }  from './commands/alerts';
import { trafficCommand } from './commands/traffic';
import { blockIpCommand } from './commands/block-ip';
import { sitesCommand }   from './commands/sites';
import { statsCommand }   from './commands/stats';
import { analyzeCommand } from './commands/analyze';

function banner() {
  const art = figlet.textSync('SENTINEL', { font: 'Small' });
  console.log(gradient(['#00eaff', '#0066ff', '#aa00ff'])(art));
  console.log(
    boxen(
      chalk.cyanBright.bold('  SENTINEL — AI Security Layer for the Agentic Internet  ') + '\n' +
      chalk.gray('  Powered by Groq · Civic Governance · Playwright Sandbox\n') +
      chalk.gray('  Usage: sentinel <command> [options]'),
      {
        padding: { top: 0, bottom: 0, left: 1, right: 1 },
        borderStyle: 'double',
        borderColor: 'cyan',
      }
    )
  );
  console.log();
}

const program = new Command();

program
  .name('sentinel')
  .description('SENTINEL CLI — AI Security for the Agentic Internet')
  .version('2.0.0')
  .hook('preAction', () => banner());

program
  .command('scan <url>')
  .description('Scan a website in the Playwright sandbox')
  .action(async (url: string) => {
    await scanCommand(url);
  });

program
  .command('analyze <url>')
  .description('Run deep AI threat analysis on a URL (Groq Llama-3.3-70B)')
  .action(async (url: string) => {
    await analyzeCommand(url);
  });

program
  .command('sandbox <url>')
  .description('Run sandbox scan with full execution log')
  .action(async (url: string) => {
    await sandboxCommand(url);
  });

program
  .command('alerts')
  .description('Show active threat alerts')
  .option('-l, --limit <n>', 'Max alerts to show', '20')
  .action(async (opts: { limit: string }) => {
    await alertsCommand(parseInt(opts.limit));
  });

program
  .command('traffic')
  .description('Show live traffic stream')
  .option('-l, --limit <n>', 'Max entries to show', '30')
  .action(async (opts: { limit: string }) => {
    await trafficCommand(parseInt(opts.limit));
  });

program
  .command('block-ip <ip>')
  .description('Block an IP address via the response engine + Civic governance')
  .action(async (ip: string) => {
    await blockIpCommand(ip);
  });

program
  .command('sites')
  .description('Show recent sandbox-scanned sites')
  .action(async () => {
    await sitesCommand();
  });

program
  .command('stats')
  .description('Show system security status')
  .action(async () => {
    await statsCommand();
  });

program
  .command('clearance <url>')
  .description('Run agent clearance check — same as the /api/v1/agent/clearance API')
  .option('-k, --key <apiKey>', 'Agent API key', 'sk-sentinel-demo0000')
  .option('-c, --context <ctx>', 'Context about what the agent is doing', 'CLI check')
  .action(async (url: string, opts: { key: string; context: string }) => {
    const axios = (await import('axios')).default;
    const { getBaseUrl } = await import('./utils');
    const ora   = (await import('ora')).default;
    const chalk_mod = (await import('chalk')).default;

    const spinner = ora({ text: chalk_mod.cyan('Running agent clearance check...'), color: 'cyan' }).start();
    try {
      const res = await axios.post(`${getBaseUrl()}/api/v1/agent/clearance`, {
        agentId:  'sentinel-cli',
        url,
        context:  opts.context,
        agentKey: opts.key,
      }, { timeout: 30000 });
      spinner.succeed(chalk_mod.green('Clearance check complete'));

      const d = res.data;
      console.log('');
      const granted = d.clearanceGranted;
      const banner = granted
        ? chalk_mod.bgGreen.black.bold(' ✓ CLEARANCE GRANTED ')
        : chalk_mod.bgRed.white.bold(' ⛔ CLEARANCE DENIED ');

      console.log(banner + chalk_mod.gray(` — ${d.overallRisk?.toUpperCase()} risk (${d.riskScore}/100)`));
      console.log('');
      console.log(chalk_mod.gray('  REASON:   ') + chalk_mod.white(d.reason ?? 'No reason'));
      console.log(chalk_mod.gray('  ACTION:   ') + chalk_mod.yellow(d.suggestedAction));
      console.log(chalk_mod.gray('  AUDIT ID: ') + chalk_mod.cyan(d.auditId));
      console.log(chalk_mod.gray('  REVIEW:   ') + chalk_mod.cyan(d.humanReviewUrl));

      if (d.threats?.length > 0) {
        console.log('');
        console.log(chalk_mod.gray('  THREATS FOUND:'));
        d.threats.forEach((t: string) => console.log(chalk_mod.gray('  ·') + chalk_mod.red(` ${t}`)));
      }
      console.log('');
    } catch (err: any) {
      spinner.fail(chalk_mod.red('Clearance check failed'));
      console.log(chalk_mod.red(`  ${err?.message}`));
    }
  });

program.parse(process.argv);
