import { spawn, ChildProcess } from 'child_process';
import * as readline from 'readline';
import { SSRFGuardTS } from '../core/ssrf_guard.js';
import { PromptSanitizerTS } from '../core/prompt_sanitizer.js';
import { RiskEngineTS, ToolRiskTier } from '../core/risk_engine.js';
import { SecurityLedgerTS } from '../core/ledger.js';

export class MCPProxy {
  private targetProcess: ChildProcess | null = null;
  private ledger: SecurityLedgerTS;

  constructor(private targetCommand: string, private targetArgs: string[] = []) {
    this.ledger = new SecurityLedgerTS();
  }

  public start(): void {
    console.error(`[Tcha Protection] Initializing In-Line MCP STDIO Proxy...`);
    console.error(`[Tcha Protection] Target: ${this.targetCommand} ${this.targetArgs.join(' ')}`);

    this.targetProcess = spawn(this.targetCommand, this.targetArgs, {
      stdio: ['pipe', 'pipe', 'inherit'],
      shell: process.platform === 'win32',
    });

    this.targetProcess.on('error', (err) => {
      console.error(`[Tcha Protection] Target process spawn error: ${err.message}`);
    });

    if (!this.targetProcess.stdin || !this.targetProcess.stdout) {
      console.error('[Tcha Protection] Fatal: Failed to bind child process STDIO streams.');
      process.exit(1);
    }

    // 1. Process responses from Target Server -> Host Agent
    const targetReader = readline.createInterface({ input: this.targetProcess.stdout });
    targetReader.on('line', (line) => {
      // Forward downstream response directly to Host Agent stdout
      process.stdout.write(line + '\n');
    });

    // 2. Process requests from Host Agent -> Target Server
    const hostReader = readline.createInterface({ input: process.stdin });
    hostReader.on('line', async (line) => {
      if (!line.trim()) return;

      try {
        const msg = JSON.parse(line);

        // Check if message is a tool execution request (MCP tools/call)
        if (msg.method === 'tools/call' && msg.params) {
          const toolName = msg.params.name || '';
          const args = msg.params.arguments || {};

          // A. SSRF & Network Egress Gate
          if (args.url && typeof args.url === 'string') {
            const ssrfCheck = await SSRFGuardTS.isSafeUrl(args.url);
            if (!ssrfCheck.safe) {
              console.error(`[Tcha FIREWALL] Intercepted SSRF attempt to: ${args.url} (${ssrfCheck.reason})`);

              this.ledger.recordEvent({
                eventType: 'SSRF_BLOCKED',
                severity: 'CRITICAL',
                targetTool: toolName,
                sourceAgent: 'host_agent',
                rawPayload: JSON.stringify(args),
                sanitizedPayload: '',
                actionTaken: 'BLOCKED',
              });

              const errorResponse = {
                jsonrpc: '2.0',
                id: msg.id,
                error: {
                  code: -32001,
                  message: `Blocked by Tcha Protection: SSRF Egress attempt (${ssrfCheck.reason})`,
                  data: {
                    threat_type: 'SSRF_EGRESS',
                    rule_id: 'SEC-SSRF-001',
                    target_url: args.url,
                  },
                },
              };

              process.stdout.write(JSON.stringify(errorResponse) + '\n');
              return;
            }
          }

          // B. Path Traversal & Shell Metacharacter Gate
          const argCheck = RiskEngineTS.inspectArguments(args);
          if (argCheck.suspicious) {
            console.error(`[Tcha FIREWALL] Intercepted path traversal/shell injection: ${argCheck.reason}`);

            this.ledger.recordEvent({
              eventType: 'INJECTION_BLOCKED',
              severity: 'HIGH',
              targetTool: toolName,
              sourceAgent: 'host_agent',
              rawPayload: JSON.stringify(args),
              sanitizedPayload: '',
              actionTaken: 'BLOCKED',
            });

            const errorResponse = {
              jsonrpc: '2.0',
              id: msg.id,
              error: {
                code: -32001,
                message: `Blocked by Tcha Protection: Path traversal or shell metacharacter detected (${argCheck.reason})`,
                data: {
                  threat_type: 'COMMAND_OR_PATH_INJECTION',
                  rule_id: 'SEC-TRAV-002',
                },
              },
            };

            process.stdout.write(JSON.stringify(errorResponse) + '\n');
            return;
          }

          // C. Tool Risk Classification & Tier 3 HITL Authorization Gate
          const classification = RiskEngineTS.classifyTool(toolName, args);
          if (classification.tier === ToolRiskTier.TIER_3_DESTRUCTIVE) {
            // Check for signed HMAC approval token
            const providedToken = args.approval_token || msg.params.approval_token;
            const challengePayload = args.challenge_payload || msg.params.challenge_payload;

            let authorized = false;
            if (providedToken && challengePayload) {
              const verifyRes = RiskEngineTS.verifyHitlApproval(challengePayload, providedToken);
              if (verifyRes.valid) {
                authorized = true;
                console.error(`[Tcha HITL] Tier 3 action '${toolName}' verified with authentic cryptographic token.`);
                this.ledger.recordEvent({
                  eventType: 'HITL_APPROVED',
                  severity: 'INFO',
                  targetTool: toolName,
                  sourceAgent: 'host_agent',
                  rawPayload: JSON.stringify(args),
                  sanitizedPayload: JSON.stringify(args),
                  actionTaken: 'ALLOWED_APPROVED',
                });
              }
            }

            if (!authorized) {
              console.error(`[Tcha GUARD] Suspended Tier 3 destructive call: ${toolName}`);
              const challenge = RiskEngineTS.generateHitlChallenge(toolName, args);

              this.ledger.recordEvent({
                eventType: 'HITL_CHALLENGE',
                severity: 'HIGH',
                targetTool: toolName,
                sourceAgent: 'host_agent',
                rawPayload: JSON.stringify(args),
                sanitizedPayload: '',
                actionTaken: 'SUSPENDED_HITL',
              });

              const errorResponse = {
                jsonrpc: '2.0',
                id: msg.id,
                error: {
                  code: -32001,
                  message: `[Tcha Guard]: High-risk Tier 3 tool invocation suspended awaiting human authorization (${classification.reason})`,
                  data: {
                    threat_type: 'UNAUTHORIZED_TIER3_ACTION',
                    rule_id: 'SEC-HITL-003',
                    challenge,
                  },
                },
              };

              process.stdout.write(JSON.stringify(errorResponse) + '\n');
              return;
            }
          } else {
            // Safe read-only or standard mutating tool
            this.ledger.recordEvent({
              eventType: 'TOOL_EXECUTION',
              severity: 'INFO',
              targetTool: toolName,
              sourceAgent: 'host_agent',
              rawPayload: JSON.stringify(args),
              sanitizedPayload: JSON.stringify(args),
              actionTaken: 'ALLOWED',
            });
          }
        }

        // Forward clean request to target MCP server process
        this.targetProcess?.stdin?.write(line + '\n');
      } catch (err: any) {
        console.error(`[Tcha Protection] Proxy stream parsing warning: ${err.message}`);
        this.targetProcess?.stdin?.write(line + '\n');
      }
    });

    this.targetProcess.on('exit', (code) => {
      console.error(`[Tcha Protection] Target MCP server process exited with code ${code}`);
      process.exit(code || 0);
    });
  }
}
