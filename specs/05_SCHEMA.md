# 05. Database Schema & API Contracts (SCHEMA) — AgentShield Pro 2.0

## 1. SQLite Relational Schema & Merkle Audit Ledger

All events, probes, and proxy intercepts are stored in `agentshield.db`. Every row is cryptographically bound to the previous row using continuous SHA-256 hash chaining:

```sql
-- 1. Audit Sessions Table
CREATE TABLE IF NOT EXISTS audit_sessions (
    id TEXT PRIMARY KEY,                       -- UUID v4
    started_at TEXT NOT NULL,                  -- ISO 8601 UTC timestamp
    completed_at TEXT,                         -- ISO 8601 UTC timestamp
    target_name TEXT NOT NULL,                 -- Name of agent or MCP server under test
    total_probes INTEGER NOT NULL DEFAULT 0,
    passed_probes INTEGER NOT NULL DEFAULT 0,
    resilience_score REAL NOT NULL DEFAULT 0.0,
    grade TEXT NOT NULL,                       -- A+, A, B, C, D, F
    merkle_root_hash TEXT NOT NULL             -- SHA-256 Merkle root of this session
);

-- 2. Audit Probes Detail Table
CREATE TABLE IF NOT EXISTS audit_probes (
    id TEXT PRIMARY KEY,                       -- UUID v4
    session_id TEXT NOT NULL REFERENCES audit_sessions(id) ON DELETE CASCADE,
    probe_number INTEGER NOT NULL,             -- 1 to 100
    category TEXT NOT NULL,                    -- prompt_injection, ssrf, traversal, steganography, tool_privilege
    attack_vector TEXT NOT NULL,               -- e.g., 'ascii_smuggling', 'metadata_impersonation'
    payload TEXT NOT NULL,                     -- Exact probe payload
    status TEXT NOT NULL,                      -- 'NEUTRALIZED' | 'BYPASSED'
    remediation TEXT,
    created_at TEXT NOT NULL
);

-- 3. Tamper-Evident Event Ledger (Merkle Chained)
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_uuid TEXT UNIQUE NOT NULL,
    timestamp TEXT NOT NULL,                   -- ISO 8601 UTC
    event_type TEXT NOT NULL,                  -- 'PROMPT_SANITIZED', 'SSRF_BLOCKED', 'TOOL_INTERCEPTED', 'HITL_APPROVED'
    risk_tier INTEGER NOT NULL,                -- 1 (Safe), 2 (Mutating), 3 (Destructive)
    tool_name TEXT,
    tool_arguments TEXT,                       -- JSON string
    decision TEXT NOT NULL,                    -- 'PASS', 'BLOCK', 'CHALLENGE', 'APPROVED', 'REJECTED'
    previous_hash TEXT NOT NULL,               -- SHA-256 of the prior row
    current_hash TEXT NOT NULL                 -- SHA-256(id + timestamp + event_type + tool_name + decision + previous_hash)
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_probes_session ON audit_probes(session_id);
```

---

## 2. In-Line MCP Proxy Protocol Contract (JSON-RPC 2.0)

When wrapping an MCP server, AgentShield intercepts requests conforming to the Model Context Protocol Specification:

* **Interception Target:** `tools/call` methods.
* **Request Schema:**
  ```json
  {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "read_file",
      "arguments": {
        "path": "/etc/passwd"
      }
    }
  }
  ```
* **Proxy Decision Logic:**
  1. If arguments trigger `Path Traversal` or `SSRF Egress`, respond immediately with a standardized JSON-RPC error without touching the downstream server:
     ```json
     {
       "jsonrpc": "2.0",
       "id": 1,
       "error": {
         "code": -32001,
         "message": "Blocked by AgentShield Pro: SSRF Egress attempt to cloud metadata (169.254.169.254)",
         "data": {
           "threat_type": "SSRF_EGRESS",
           "rule_id": "SEC-SSRF-001"
         }
       }
     }
     ```
  2. If the tool is categorized as **Tier 3 (Destructive)**, block execution and emit an HMAC challenge requiring verification before downstream dispatch.
