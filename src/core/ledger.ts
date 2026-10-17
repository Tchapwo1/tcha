import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { WebhookNotifierTS } from './webhook_notifier.js';

export interface SecurityEventData {
  id?: string;
  timestamp?: number;
  eventType: string;
  severity: string;
  targetTool: string;
  sourceAgent: string;
  rawPayload: string;
  sanitizedPayload: string;
  actionTaken: string;
}

export class SecurityLedgerTS {
  private logFilePath: string;
  private latestHash: string = '0'.repeat(64);

  constructor(baseDir: string = process.cwd()) {
    this.logFilePath = path.join(baseDir, 'agentshield_events.jsonl');
    this.hydrateLatestHash();
  }

  private hydrateLatestHash(): void {
    if (!fs.existsSync(this.logFilePath)) return;
    try {
      const lines = fs.readFileSync(this.logFilePath, 'utf-8').trim().split('\n');
      if (lines.length > 0 && lines[lines.length - 1]) {
        const lastEvent = JSON.parse(lines[lines.length - 1]);
        if (lastEvent.merkleHash) {
          this.latestHash = lastEvent.merkleHash;
        }
      }
    } catch {
      this.latestHash = '0'.repeat(64);
    }
  }

  public recordEvent(data: SecurityEventData) {
    const id = data.id || crypto.randomUUID();
    const timestamp = data.timestamp || Date.now();
    const prevHash = this.latestHash;

    const hashInput = `${prevHash}:${id}:${timestamp}:${data.eventType}:${data.rawPayload || ''}`;
    const merkleHash = crypto.createHash('sha256').update(hashInput).digest('hex');

    const record = {
      id,
      timestamp,
      eventType: data.eventType,
      severity: data.severity,
      targetTool: data.targetTool,
      sourceAgent: data.sourceAgent,
      rawPayload: data.rawPayload,
      sanitizedPayload: data.sanitizedPayload,
      actionTaken: data.actionTaken,
      prevHash,
      merkleHash,
    };

    fs.appendFileSync(this.logFilePath, JSON.stringify(record) + '\n', 'utf-8');
    this.latestHash = merkleHash;

    // Asynchronously dispatch webhook notifications for high-risk and critical events
    WebhookNotifierTS.dispatchAsync(record);

    return record;
  }

  public verifyIntegrity(): { valid: boolean; count: number; message: string } {
    if (!fs.existsSync(this.logFilePath)) {
      return { valid: true, count: 0, message: 'Ledger is empty and valid.' };
    }

    const lines = fs.readFileSync(this.logFilePath, 'utf-8').trim().split('\n');
    let expectedPrev = '0'.repeat(64);

    for (let i = 0; i < lines.length; i++) {
      if (!lines[i].trim()) continue;
      const row = JSON.parse(lines[i]);

      if (row.prevHash !== expectedPrev) {
        return {
          valid: false,
          count: i,
          message: `Broken chain pointer at row ${i + 1}. Expected ${expectedPrev}, got ${row.prevHash}`,
        };
      }

      const hashInput = `${row.prevHash}:${row.id}:${row.timestamp}:${row.eventType}:${row.rawPayload || ''}`;
      const computed = crypto.createHash('sha256').update(hashInput).digest('hex');

      if (computed !== row.merkleHash) {
        return {
          valid: false,
          count: i,
          message: `Tampered hash at row ${i + 1}. Integrity violation.`,
        };
      }

      expectedPrev = row.merkleHash;
    }

    return { valid: true, count: lines.length, message: `Verified ${lines.length} events successfully.` };
  }
}
