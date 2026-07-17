import axios from 'axios';
import chalk from 'chalk';
import ora from 'ora';
import Table from 'cli-table3';
import { getBaseUrl, riskColor, levelColor, severityBadge } from '../utils';

export async function analyzeCommand(url: string) {
  const base    = getBaseUrl();
  const spinner = ora({ text: chalk.cyan('Running AI deep analysis...'), color: 'cyan' }).start();

  let domain = url;
  try { domain = new URL(url.startsWith('http') ? url : 'https://' + url).hostname; } catch {}
  const fullUrl = url.startsWith('http') ? url : 'https://' + url;

  try {
    // Call Groq analysis endpoint
    const res = await axios.post(`${base}/api/groq-analyze`, {
      url:      fullUrl,
      domain,
      cookies:  [],
      scripts:  [],
      forms:    [],
    }, { timeout: 30000 });

    spinner.succeed(chalk.green('AI analysis complete'));
    const d = res.data;

    // ── Header ──────────────────────────────────────────────
    console.log('');
    console.log(
      chalk.bold.cyan('┌─ SENTINEL // AI THREAT ANALYSIS ──────────────────────────┐')
    );
    console.log(chalk.cyan(`│  URL: ${chalk.white(fullUrl.slice(0, 56))}`));
    console.log(
      chalk.cyan(`│  RISK: ${chalk.bold(String(d.riskScore ?? 0).padEnd(4))}`) +
      riskColor(d.riskScore ?? 0)(`[${
        (d.riskScore ?? 0) >= 80 ? '████████' :
        (d.riskScore ?? 0) >= 60 ? '██████░░' :
        (d.riskScore ?? 0) >= 35 ? '████░░░░' : '██░░░░░░'
      }] ${d.riskScore ?? 0}/100`)
    );
    console.log(
      chalk.cyan('│  SEVERITY: ') + severityBadge(d.severity ?? 'safe') +
      chalk.cyan('  ATTACK_TYPE: ') + chalk.yellow(d.attackType ?? 'none')
    );
    console.log(chalk.bold.cyan('└────────────────────────────────────────────────────────────┘'));
    console.log('');

    // ── Summary ──────────────────────────────────────────────
    if (d.summary) {
      console.log(chalk.gray('// AI_SUMMARY'));
      console.log(chalk.white(`   ${d.summary}`));
      console.log('');
    }

    // ── Threats table ─────────────────────────────────────────
    if (d.threats?.length > 0) {
      const threatTable = new Table({
        head: [
          chalk.cyan('LEVEL'),
          chalk.cyan('THREAT'),
        ],
        colWidths:   [12, 60],
        style:       { border: ['gray'], head: [] },
        chars: { mid: '─', 'left-mid': '├', 'right-mid': '┤', middle: '┼' },
      });

      d.threats.forEach((t: string) => {
        // Infer level from text keywords
        const level =
          t.toLowerCase().includes('critical') || t.toLowerCase().includes('no https') ? 'critical' :
          t.toLowerCase().includes('high')     || t.toLowerCase().includes('session')  ? 'high' :
          t.toLowerCase().includes('medium')   || t.toLowerCase().includes('missing')  ? 'medium' : 'low';

        threatTable.push([
          chalk.hex(levelColor(level)).bold(level.toUpperCase()),
          chalk.gray(t.slice(0, 58)),
        ]);
      });

      console.log(chalk.gray('// DETECTED_THREATS'));
      console.log(threatTable.toString());
      console.log('');
    } else {
      console.log(chalk.green('✓ No significant threats detected'));
      console.log('');
    }

    // ── Recommendations ───────────────────────────────────────
    if (d.recommendations?.length > 0) {
      console.log(chalk.gray('// AI_RECOMMENDATIONS'));
      d.recommendations.slice(0, 5).forEach((r: string, i: number) => {
        console.log(chalk.cyan(`  AI> `) + chalk.white(r));
      });
      console.log('');
    }

    // ── Scores ────────────────────────────────────────────────
    const scoreTable = new Table({
      head: [chalk.cyan('METRIC'), chalk.cyan('VALUE'), chalk.cyan('STATUS')],
      colWidths: [22, 12, 20],
      style: { border: ['gray'], head: [] },
    });

    scoreTable.push(
      [chalk.white('RISK SCORE'),     riskColor(d.riskScore ?? 0)(`${d.riskScore ?? 0}/100`),     riskBadge(d.riskScore ?? 0)],
      [chalk.white('SECURITY SCORE'), riskColor(100 - (d.riskScore ?? 0))(`${d.securityScore ?? (100 - (d.riskScore ?? 0))}/100`), ''],
      [chalk.white('ATTACK TYPE'),    chalk.yellow(d.attackType ?? 'none'), ''],
      [chalk.white('SEVERITY'),       severityBadge(d.severity ?? 'safe'), ''],
    );

    console.log(chalk.gray('// ANALYSIS_SCORES'));
    console.log(scoreTable.toString());
    console.log('');

    console.log(chalk.gray(`// Powered by Groq Llama-3.3-70B • SENTINEL v2.0`));
    console.log('');

  } catch (err: any) {
    spinner.fail(chalk.red('AI analysis failed'));
    if (err?.response?.status === 500) {
      console.log(chalk.red('  API returned error — check GROQ_API_KEY is configured'));
    } else {
      console.log(chalk.red(`  ${err?.message ?? 'Unknown error'}`));
    }
  }
}

function riskBadge(score: number): string {
  if (score >= 80) return chalk.bgRed.black(' CRITICAL ');
  if (score >= 60) return chalk.bgYellow.black(' HIGH     ');
  if (score >= 35) return chalk.bgHex('#f97316').black(' MEDIUM   ');
  return chalk.bgGreen.black(' SAFE     ');
}
