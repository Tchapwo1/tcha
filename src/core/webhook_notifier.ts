import * as crypto from 'crypto';
import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';
import { SecurityEventData } from './ledger.js';

export type WebhookProvider = 'slack' | 'discord' | 'generic';

export interface WebhookConfig {
  url?: string;
  provider?: WebhookProvider;
  secret?: string;
  minSeverity?: 'INFO' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  enabled?: boolean;
}

export class WebhookNotifierTS {
  private static config: WebhookConfig = {
    url: process.env.AGENTSHIELD_WEBHOOK_URL || '',
    provider: (process.env.AGENTSHIELD_WEBHOOK_TYPE as WebhookProvider) || 'generic',
    secret: process.env.AGENTSHIELD_WEBHOOK_SECRET || '',
    minSeverity: (process.env.AGENTSHIELD_WEBHOOK_MIN_SEVERITY as any) || 'HIGH',
    enabled: Boolean(process.env.AGENTSHIELD_WEBHOOK_URL),
  };

  private static recentAlerts = new Map<string, number>();
  private static DEDUP_WINDOW_MS = 60000; // 1 minute alert deduplication

  public static setConfig(newConfig: Partial<WebhookConfig>): WebhookConfig {
    this.config = { ...this.config, ...newConfig };
    if (this.config.url && !newConfig.provider) {
      this.config.provider = this.detectProvider(this.config.url);
    }
    this.config.enabled = Boolean(this.config.url);
    return this.config;
  }

  public static getConfig(): WebhookConfig {
    return { ...this.config };
  }

  public static detectProvider(url: string): WebhookProvider {
    const lower = url.toLowerCase();
    if (lower.includes('hooks.slack.com') || lower.includes('slack.com/services')) {
      return 'slack';
    }
    if (lower.includes('discord.com/api/webhooks') || lower.includes('discordapp.com/api/webhooks')) {
      return 'discord';
    }
    return 'generic';
  }

  private static shouldAlert(severity: string): boolean {
    if (!this.config.enabled || !this.config.url) return false;

    const levels = ['INFO', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const minIndex = levels.indexOf(this.config.minSeverity || 'HIGH');
    const eventIndex = levels.indexOf(severity.toUpperCase());

    return eventIndex >= minIndex;
  }

  public static formatSlackPayload(event: SecurityEventData) {
    const isCritical = event.severity === 'CRITICAL' || event.actionTaken === 'BLOCKED';
    const emoji = isCritical ? '🚨' : event.severity === 'HIGH' ? '⚠️' : '🛡️';
    const color = isCritical ? '#ef4444' : event.severity === 'HIGH' ? '#f59e0b' : '#10b981';

    return {
      text: `${emoji} [AgentShield Security Alert]: ${event.eventType} on \`${event.targetTool}\``,
      attachments: [
        {
          color,
          blocks: [
            {
              type: 'header',
              text: {
                type: 'plain_text',
                text: `${emoji} AgentShield: ${event.eventType}`,
                emoji: true,
              },
            },
            {
              type: 'section',
              fields: [
                { type: 'mrkdwn', text: `*Severity:*\n\`${event.severity}\`` },
                { type: 'mrkdwn', text: `*Action Taken:*\n\`${event.actionTaken}\`` },
                { type: 'mrkdwn', text: `*Target Tool:*\n\`${event.targetTool}\`` },
                { type: 'mrkdwn', text: `*Source Agent:*\n\`${event.sourceAgent || 'agent_client'}\`` },
              ],
            },
            {
              type: 'section',
              text: {
                type: 'mrkdwn',
                text: `*Payload Snippet:*\n\`\`\`${(event.rawPayload || '{}').slice(0, 300)}\`\`\``,
              },
            },
            {
              type: 'context',
              elements: [
                {
                  type: 'mrkdwn',
                  text: `🔒 *AgentShield Gateway* | Timestamp: ${new Date(event.timestamp || Date.now()).toISOString()} | Zero-Trust Interceptor`,
                },
              ],
            },
          ],
        },
      ],
    };
  }

  public static formatDiscordPayload(event: SecurityEventData) {
    const isCritical = event.severity === 'CRITICAL' || event.actionTaken === 'BLOCKED';
    const color = isCritical ? 0xef4444 : event.severity === 'HIGH' ? 0xf59e0b : 0x10b981;

    return {
      username: 'AgentShield Security Gateway',
      avatar_url: 'https://raw.githubusercontent.com/agentshield/branding/main/shield-icon.png',
      embeds: [
        {
          title: `🛡️ Security Alert: ${event.eventType}`,
          description: `An intercepted tool invocation required automated defensive mitigation.`,
          color,
          fields: [
            { name: 'Target Tool', value: `\`${event.targetTool}\``, inline: true },
            { name: 'Action Taken', value: `**${event.actionTaken}**`, inline: true },
            { name: 'Severity', value: `\`${event.severity}\``, inline: true },
            {
              name: 'Intercepted Payload',
              value: `\`\`\`json\n${(event.rawPayload || '{}').slice(0, 500)}\n\`\`\``,
              inline: false,
            },
          ],
          footer: {
            text: `AgentShield v1.1.0 • Cryptographic Merkle Ledger Active`,
          },
          timestamp: new Date(event.timestamp || Date.now()).toISOString(),
        },
      ],
    };
  }

  public static formatGenericPayload(event: SecurityEventData) {
    return {
      agentShieldAlert: true,
      version: '1.1.0',
      timestamp: event.timestamp || Date.now(),
      event: {
        id: event.id,
        eventType: event.eventType,
        severity: event.severity,
        targetTool: event.targetTool,
        sourceAgent: event.sourceAgent,
        actionTaken: event.actionTaken,
        rawPayload: event.rawPayload,
      },
    };
  }

  public static async dispatch(event: SecurityEventData, overrideUrl?: string): Promise<{ success: boolean; status?: number; error?: string }> {
    const targetUrl = overrideUrl || this.config.url;
    if (!targetUrl) {
      return { success: false, error: 'No webhook URL configured.' };
    }

    if (!overrideUrl && !this.shouldAlert(event.severity)) {
      return { success: true, error: 'Filtered by minSeverity threshold.' };
    }

    // Rate-limiting / deduplication
    const dedupKey = `${event.eventType}:${event.targetTool}:${(event.rawPayload || '').slice(0, 50)}`;
    const now = Date.now();
    const lastSeen = this.recentAlerts.get(dedupKey) || 0;

    if (!overrideUrl && now - lastSeen < this.DEDUP_WINDOW_MS) {
      return { success: true, error: 'Deduplicated: alert sent recently within 60s window.' };
    }
    this.recentAlerts.set(dedupKey, now);

    const provider = overrideUrl ? this.detectProvider(targetUrl) : (this.config.provider || this.detectProvider(targetUrl));

    let bodyData: any;
    if (provider === 'slack') {
      bodyData = this.formatSlackPayload(event);
    } else if (provider === 'discord') {
      bodyData = this.formatDiscordPayload(event);
    } else {
      bodyData = this.formatGenericPayload(event);
    }

    const payloadString = JSON.stringify(bodyData);
    const parsedUrl = new URL(targetUrl);
    const isHttps = parsedUrl.protocol === 'https:';

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payloadString).toString(),
      'User-Agent': 'AgentShield-Security-Gateway/1.1.0',
    };

    if (this.config.secret) {
      const hmac = crypto.createHmac('sha256', this.config.secret).update(payloadString).digest('hex');
      headers['X-AgentShield-Signature'] = `sha256=${hmac}`;
    }

    return new Promise((resolve) => {
      const transport = isHttps ? https : http;
      const req = transport.request(
        parsedUrl,
        {
          method: 'POST',
          headers,
          timeout: 5000,
        },
        (res) => {
          let resData = '';
          res.on('data', (chunk) => (resData += chunk));
          res.on('end', () => {
            const success = (res.statusCode || 0) >= 200 && (res.statusCode || 0) < 300;
            resolve({
              success,
              status: res.statusCode,
              error: success ? undefined : `HTTP ${res.statusCode}: ${resData.slice(0, 100)}`,
            });
          });
        }
      );

      req.on('error', (err) => {
        resolve({ success: false, error: err.message });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({ success: false, error: 'Webhook connection timed out (5s).' });
      });

      req.write(payloadString);
      req.end();
    });
  }

  public static dispatchAsync(event: SecurityEventData): void {
    // Non-blocking fire-and-forget to ensure zero latency overhead on agent execution
    if (this.shouldAlert(event.severity)) {
      this.dispatch(event).catch((err) => {
        console.error(`[AgentShield Webhook Warning]: Failed to dispatch alert: ${err.message}`);
      });
    }
  }

  public static async sendTestAlert(url?: string): Promise<{ success: boolean; error?: string; status?: number }> {
    const testEvent: SecurityEventData = {
      id: crypto.randomUUID(),
      timestamp: Date.now(),
      eventType: 'SSRF_ATTEMPT',
      severity: 'CRITICAL',
      targetTool: 'fetch_url',
      sourceAgent: 'test_agent_probe',
      rawPayload: JSON.stringify({ url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' }),
      sanitizedPayload: '',
      actionTaken: 'BLOCKED',
    };

    return this.dispatch(testEvent, url);
  }
}
