import * as crypto from 'crypto';

const DEFAULT_SECRET_KEY = Buffer.from('agentshield_local_dev_secret_key_994821', 'utf-8');

export enum ToolRiskTier {
  TIER_1_READ_ONLY = 'TIER_1_READ_ONLY',
  TIER_2_MUTATING = 'TIER_2_MUTATING',
  TIER_3_DESTRUCTIVE = 'TIER_3_DESTRUCTIVE',
}

const TIER_3_KEYWORDS = [
  'delete', 'remove', 'drop', 'destroy', 'truncate', 'purge', 'erase',
  'bash', 'sh', 'exec', 'shell', 'eval', 'sudo', 'kill', 'spawn', 'powershell',
  'transfer', 'pay', 'charge', 'refund', 'purchase', 'modify_payroll',
  'grant_admin', 'disable_firewall', 'reset_mfa', 'rotate_root', 'bypass_auth',
  'overwrite_agent_memory', 'poison', 'corrupt', 'inject_rag'
];

const TIER_1_KEYWORDS = [
  'read', 'get', 'fetch', 'list', 'search', 'inspect', 'view',
  'check', 'scan', 'status', 'count', 'metrics', 'find'
];

export class RiskEngineTS {
  public static inspectArguments(params: Record<string, any>): { suspicious: boolean; reason: string } {
    if (!params) return { suspicious: false, reason: '' };
    const tokens = [';', '|', '$(', '`', '..', '&&', '&', '%2e%2e', '%2f', '%5c'];
    for (const [key, val] of Object.entries(params)) {
      const strVal = String(val);
      for (const tok of tokens) {
        if (strVal.includes(tok)) {
          return { suspicious: true, reason: `Suspicious token '${tok}' in argument '${key}'` };
        }
      }
    }
    return { suspicious: false, reason: '' };
  }

  public static classifyTool(toolName: string, params?: Record<string, any>): { tier: ToolRiskTier; reason: string } {
    const lower = toolName.toLowerCase();

    for (const kw of TIER_3_KEYWORDS) {
      if (lower.includes(kw)) {
        return {
          tier: ToolRiskTier.TIER_3_DESTRUCTIVE,
          reason: `Tool '${toolName}' matches destructive/privilege pattern '${kw}'.`
        };
      }
    }

    if (params) {
      const argCheck = this.inspectArguments(params);
      if (argCheck.suspicious) {
        return {
          tier: ToolRiskTier.TIER_3_DESTRUCTIVE,
          reason: `Tool '${toolName}' rejected: ${argCheck.reason}`
        };
      }
    }

    for (const kw of TIER_1_KEYWORDS) {
      if (lower.includes(kw)) {
        return {
          tier: ToolRiskTier.TIER_1_READ_ONLY,
          reason: `Tool '${toolName}' matches safe read-only pattern '${kw}'.`
        };
      }
    }

    return {
      tier: ToolRiskTier.TIER_2_MUTATING,
      reason: `Tool '${toolName}' is classified as state-mutating.`
    };
  }

  public static generateHitlChallenge(toolName: string, params: Record<string, any>, ttlSeconds: number = 300) {
    const timestamp = Math.floor(Date.now() / 1000);
    const expiresAt = timestamp + ttlSeconds;
    const sortedParams = JSON.stringify(params, Object.keys(params).sort());
    const challengePayload = `${toolName}:${sortedParams}:${expiresAt}`;

    const token = crypto.createHmac('sha256', DEFAULT_SECRET_KEY)
      .update(challengePayload)
      .digest('hex');

    return {
      toolName,
      params,
      createdAt: timestamp,
      expiresAt,
      approvalToken: token,
      challengePayload,
      status: 'PENDING_APPROVAL'
    };
  }

  public static verifyHitlApproval(challengePayload: string, providedToken: string): { valid: boolean; reason: string } {
    try {
      const parts = challengePayload.split(':');
      const expiresAt = parseInt(parts[parts.length - 1], 10);
      const now = Math.floor(Date.now() / 1000);

      if (now > expiresAt) {
        return { valid: false, reason: 'Approval challenge has expired. Request a new challenge.' };
      }

      const expectedToken = crypto.createHmac('sha256', DEFAULT_SECRET_KEY)
        .update(challengePayload)
        .digest('hex');

      const expectedBuf = Buffer.from(expectedToken, 'hex');
      const providedBuf = Buffer.from(providedToken, 'hex');

      if (expectedBuf.length === providedBuf.length && crypto.timingSafeEqual(expectedBuf, providedBuf)) {
        return { valid: true, reason: 'Approval token is cryptographically valid.' };
      } else {
        return { valid: false, reason: 'Invalid HMAC signature for provided approval token.' };
      }
    } catch (err: any) {
      return { valid: false, reason: `Verification error: ${err.message}` };
    }
  }
}
