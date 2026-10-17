# 02. Technical Requirement Document (TRD) — AgentShield Pro 2.0

## 1. System Architecture & Tech Stack

AgentShield Pro is designed as a hybrid Node.js / Python system optimized for speed, zero-dependency deployment, and standards-compliant MCP integration:

* **CLI & In-Line Proxy Engine:** Node.js (v20+ / v22+ / v24+) with TypeScript 5.4.
* **Red-Teaming Engine & Security Heuristics:** Python 3.11+ / Pytest (cross-language resilience).
* **MCP Integration:** `@modelcontextprotocol/sdk` (STDIO & SSE transports, JSON-RPC 2.0).
* **Storage & Cryptographic Ledger:** SQLite3 (`sqlite3` / `better-sqlite3` and Python `sqlite3`) with continuous SHA-256 Merkle hash chaining.
* **Executive Reporter:** Zero-external-dependency self-contained HTML/CSS template (dark/light print media CSS for instant PDF export via headless Chromium or browser).

```
                      AGENTSHIELD PRO 2.0 ARCHITECTURE
                      
    +-------------------------------------------------------------+
    |                   HOST AGENT (Claude/Cursor)                |
    +-------------------------------------------------------------+
                                   | (STDIO / JSON-RPC 2.0)
                                   v
    +-------------------------------------------------------------+
    |                 AGENTSHIELD PRO IN-LINE PROXY               |
    |                                                             |
    |  [Prompt Delimiter Guard]  -->  [SSRF & Egress Firewall]     |
    |  [Path Traversal Filter]   -->  [Risk Engine & HITL Gate]    |
    |  [Cryptographic Merkle Audit Ledger (SQLite)]               |
    +-------------------------------------------------------------+
                                   | (Filtered & Approved Calls)
                                   v
    +-------------------------------------------------------------+
    |                  DOWNSTREAM MCP SERVER                      |
    |              (Filesystem / Shell / Database)                |
    +-------------------------------------------------------------+
                                   ^
                                   | (Adversarial Probes)
    +-------------------------------------------------------------+
    |              100-PROBE RED-TEAMING RUNNER                   |
    |        OWASP Top 10 for LLMs • Executive HTML/PDF Report    |
    +-------------------------------------------------------------+
```

---

## 2. File Tree Contract

```
D:\Downloads\agentshield\
├── specs\
│   ├── 01_PRD.md
│   ├── 02_TRD.md
│   ├── 03_APP_FLOW.md
│   ├── 04_UI_UX.md
│   ├── 05_SCHEMA.md
│   └── 06_IMPLEMENTATION_PLAN.md
├── src\
│   ├── cli\
│   │   ├── index.ts                     # Main CLI router (audit, wrap, verify-ledger, report)
│   │   ├── redteam_runner.py            # Expanded 100-probe adversarial test harness
│   │   └── report_generator.py          # Executive HTML & Markdown compliance report generator
│   ├── core\
│   │   ├── ssrf_guard.py / .ts          # IP resolution, cloud metadata & RFC-1918 blocker
│   │   ├── prompt_sanitizer.py / .ts    # Delimiter encapsulation & unicode steganography filter
│   │   ├── risk_engine.py / .ts         # 3-tier tool categorization & HMAC challenge generator
│   │   ├── ledger.py / .ts              # Merkle hash-chained SQLite tamper-evident ledger
│   │   └── webhook_notifier.py / .ts    # HMAC-signed webhook alert dispatcher
│   ├── proxy\
│   │   ├── mcp_proxy.ts                 # Real-time JSON-RPC 2.0 STDIO wrapper
│   │   └── server.ts                    # SSE & HTTP proxy server
│   └── ui\
│       ├── templates\
│       │   └── audit_report.html        # Museum-grade executive compliance report template
│       └── public\                      # Live cyber-defensive dashboard
├── tests\
│   ├── test_ssrf.py
│   ├── test_sanitizer.py
│   ├── test_risk_engine.py
│   ├── test_ledger.py
│   ├── test_webhook_notifier.py
│   ├── test_redteam_100.py              # Unit tests for the 100-probe suite
│   └── test_report_generator.py         # Unit tests for executive report generation
├── package.json
├── tsconfig.json
└── requirements.txt
```

---

## 3. Performance & Resource Budgets

* **Latency Overhead (In-Line Proxy):** $\le 2\text{ms}$ on read-only tools; $\le 5\text{ms}$ on mutating tool inspection.
* **RAM Footprint:** $\le 45\text{MB}$ active memory usage during proxying.
* **Audit Duration:** 100 automated probes complete in $\le 45\text{ seconds}$ on standard developer laptops.
* **Audit Report Size:** $\le 150\text{KB}$ self-contained single-file HTML (zero external CDN or web font dependencies, enabling air-gapped security viewing).
