import express from 'express';
import * as path from 'path';
import * as fs from 'fs';
import { SecurityLedgerTS } from '../core/ledger.js';
import { WebhookNotifierTS } from '../core/webhook_notifier.js';

export function startDashboardServer(port: number = 4420) {
  const app = express();
  const ledger = new SecurityLedgerTS();

  app.use(express.json());

  // Static UI files
  const publicDir = path.resolve(process.cwd(), 'src/ui/public');
  if (fs.existsSync(publicDir)) {
    app.use(express.static(publicDir));
  }

  // API Endpoints
  app.get('/api/status', (req, res) => {
    res.json({
      status: 'ACTIVE_SHIELD',
      version: '1.0.0',
      uptime: process.uptime(),
      port,
      defenseModes: ['SSRF_GUARD', 'PROMPT_SANITIZER', 'HITL_GATE', 'MERKLE_LEDGER']
    });
  });

  app.get('/api/events', (req, res) => {
    const logPath = path.resolve(process.cwd(), 'agentshield_events.jsonl');
    if (!fs.existsSync(logPath)) {
      return res.json([]);
    }
    const lines = fs.readFileSync(logPath, 'utf-8').trim().split('\n');
    const events = lines
      .filter(l => l.trim().length > 0)
      .map(l => JSON.parse(l))
      .reverse()
      .slice(0, 50);

    res.json(events);
  });

  app.get('/api/verify', (req, res) => {
    const result = ledger.verifyIntegrity();
    res.json(result);
  });

  // Webhook Alerting Endpoints
  app.get('/api/webhook/status', (req, res) => {
    const cfg = WebhookNotifierTS.getConfig();
    let masked = '';
    if (cfg.url) {
      if (cfg.url.length > 25) {
        masked = `${cfg.url.slice(0, 15)}...${cfg.url.slice(-8)}`;
      } else {
        masked = 'Configured';
      }
    }
    res.json({
      enabled: cfg.enabled,
      provider: cfg.provider,
      minSeverity: cfg.minSeverity,
      maskedUrl: masked || 'Not configured',
    });
  });

  app.post('/api/webhook/config', (req, res) => {
    const { url, secret, minSeverity } = req.body;
    const updated = WebhookNotifierTS.setConfig({ url, secret, minSeverity });
    res.json({ success: true, config: updated });
  });

  app.post('/api/webhook/test', async (req, res) => {
    const { url } = req.body || {};
    const result = await WebhookNotifierTS.sendTestAlert(url);
    res.json(result);
  });

  app.listen(port, () => {
    console.log(`\n==================================================`);
    console.log(`🛡️  AgentShield Cyber-Defensive Dashboard Active`);
    console.log(`   URL: http://localhost:${port}`);
    console.log(`==================================================\n`);
  });
}
