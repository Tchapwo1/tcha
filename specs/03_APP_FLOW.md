# 03. Application & User Flow (APP_FLOW) — AgentShield Pro 2.0

## 1. Primary User Journeys

AgentShield Pro supports three core operational workflows:

```
FLOW 1: Pre-Deployment Security Audit & Certification
[Developer / CI-CD] ---> Run: `agentshield audit --export report.html`
                             |
                             v
                 Fires 100 Adversarial Probes
                 (Injection, SSRF, Traversal, Escapes)
                             |
                             v
                 Compiles Cryptographic Merkle Root
                             |
                             v
                 Generates `report.html` (A+ Grade Certification)

FLOW 2: In-Line Runtime MCP Proxy (`agentshield wrap`)
[Host Agent (Claude/Cursor)] ---> Calls MCP Tool (JSON-RPC)
                                      |
                                      v
                          [AgentShield STDIO Proxy]
                                      |
                 +--------------------+--------------------+
                 |                                         |
         (Tier 1 / Safe)                          (Tier 3 / Destructive)
                 |                                         |
         Passes Instantly (<2ms)                  Pauses Execution
                 |                                Generates HMAC Challenge Token
                 v                                         |
         [Downstream MCP Tool]                    Requires CLI or Web UI Approval
                 |                                         |
                 +<------------------ Approved? <----------+

FLOW 3: Cryptographic Ledger Audit & Verification
[Security Auditor] ---> Run: `agentshield verify-ledger`
                            |
                            v
               Walks Merkle Hash Chain in SQLite
                            |
                 Valid? ----+----> [PASS: Chain Unbroken, 0 Tampering]
                            |
                            +----> [FAIL: Hash Mismatch at Event #X]
```

---

## 2. Mandatory System States

Every command and UI interface in AgentShield Pro must strictly handle the 4 mandatory states:

1. **Loading / Processing State:**
   * CLI: ANSI terminal animated progress bar showing real-time probe category execution (`[Phase 1/5] Running Injections...`).
   * Web: Pulsing neon-emerald indicator with active probe counter.
2. **Empty State:**
   * When no audit ledger exists: Clean instructions on how to run the first audit (`No security events recorded. Run agentshield audit to generate baseline.`).
3. **Error State:**
   * Network resolution timeout, broken downstream MCP pipe, or malformed JSON-RPC: Clear diagnostic error message with actionable recovery step. Never crash silently.
4. **Success State:**
   * Audit complete: Executive summary banner with Resilience Grade (A+, A, B, C, F), cryptographic Merkle root hash, and path to exported report.
