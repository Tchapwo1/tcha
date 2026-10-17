#!/usr/bin/env node

import { MCPProxy } from '../proxy/mcp_proxy.js';
import { SecurityLedgerTS } from '../core/ledger.js';
import { startDashboardServer } from '../proxy/server.js';
import { WebhookNotifierTS } from '../core/webhook_notifier.js';
import { spawn } from 'child_process';

const args = process.argv.slice(2);
const command = args[0] || 'help';

switch (command) {
  case 'wrap':
  case 'proxy': {
    const targetCmd = args[1];
    const targetArgs = args.slice(2);
    if (!targetCmd) {
      console.error('Usage: tcha wrap <target-command> [target-args...]');
      console.error('Example: tcha wrap npx -y @modelcontextprotocol/server-filesystem D:/data');
      process.exit(1);
    }
    const proxy = new MCPProxy(targetCmd, targetArgs);
    proxy.start();
    break;
  }

  case 'verify-ledger': {
    console.log('[Tcha Protection] Verifying cryptographic Merkle ledger...');
    const ledger = new SecurityLedgerTS();
    const result = ledger.verifyIntegrity();
    if (result.valid) {
      console.log(`[PASS] ${result.message}`);
      process.exit(0);
    } else {
      console.error(`[FAIL] ${result.message}`);
      process.exit(1);
    }
    break;
  }

  case 'start': {
    const port = parseInt(process.env.PORT || '4420', 10);
    startDashboardServer(port);
    break;
  }

  case 'audit': {
    console.log('[Tcha Protection] Launching 100-probe Red-Teaming audit suite...');
    const runnerArgs = ['src/cli/redteam_runner.py', ...args.slice(1)];
    const py = spawn('python', runnerArgs, { stdio: 'inherit' });
    py.on('exit', (code) => process.exit(code || 0));
    break;
  }

  case 'report': {
    const outPath = args[1] || 'report.html';
    console.log(`[Tcha Protection] Running 100-probe audit and compiling report to ${outPath}...`);
    const py = spawn('python', ['src/cli/redteam_runner.py', '--export', outPath], { stdio: 'inherit' });
    py.on('exit', (code) => process.exit(code || 0));
    break;
  }

  case 'webhook': {
    const sub = args[1] || 'status';
    if (sub === 'test') {
      const targetUrl = args[2];
      console.log(`[Tcha Webhook] Sending test security alert to ${targetUrl || 'configured URL'}...`);
      WebhookNotifierTS.sendTestAlert(targetUrl).then((res) => {
        if (res.success) {
          console.log(`[PASS] Webhook test delivered successfully! Status: ${res.status || 200}`);
          process.exit(0);
        } else {
          console.error(`[FAIL] Webhook test delivery failed: ${res.error}`);
          process.exit(1);
        }
      });
    } else {
      const cfg = WebhookNotifierTS.getConfig();
      console.log(`
Tcha Webhook Status:
  Enabled:      ${cfg.enabled ? 'YES' : 'NO'}
  Provider:     ${cfg.provider}
  Min Severity: ${cfg.minSeverity}
  URL:          ${cfg.url ? cfg.url.slice(0, 20) + '...' : 'Not configured (set TCHA_WEBHOOK_URL)'}
      `);
      process.exit(0);
    }
    break;
  }

  case 'help':
  default:
    console.log(`
🛡️ Tcha Protection Pro 2.0 — Autonomous Agent Security Proxy & Red-Teaming Engine

Commands:
  tcha wrap <command> [args...]      Wrap any MCP server in an in-line STDIO security firewall
  tcha audit [--export <path>]       Execute 100-probe adversarial Red-Teaming attack suite
  tcha report [path]                 Generate an air-gapped Executive Compliance Report (HTML/PDF)
  tcha verify-ledger                 Verify SHA-256 Merkle chain integrity of audit events
  tcha start                         Launch local Cyber-Defensive Security Dashboard on port 4420
  tcha webhook [status|test]         Check or test Slack/Discord/SOC webhook alerting

Commercial Documentation & Certification:
  https://github.com/tchaprotection/tcha
    `);
    process.exit(0);
}
