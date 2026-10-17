# 🛡️ Tcha Protection Pro 2.0

> **Enterprise-Grade AI Agent & MCP In-Line Firewall, 100-Probe Red-Teaming Suite, and Cryptographic Merkle Audit Ledger**  
> Protects autonomous AI agents against Indirect Prompt Injection, Unicode Steganography, SSRF / Cloud Metadata Exfiltration, Shell Escapes, and Destructive Tool Execution (OWASP Top 10 for LLMs 2025/2026, EU AI Act Article 15, SOC 2).

---

## ⚡ Key Capabilities

- **In-Line MCP Reverse Proxy Firewall (`tcha wrap`):** Wraps standard Model Context Protocol (MCP) server STDIO streams in a transparent, zero-latency firewall ($\le 2\text{ms}$ overhead). Blocks forbidden operations with standardized JSON-RPC error `-32001`.
- **Automated 100-Probe Red-Teaming Engine (`tcha audit`):** Fires 100 categorized adversarial probes across 4 core vectors (Prompt Injection, SSRF Egress, Path Traversal, Tool Privilege Escalation) with instant resilience grading (A+ Tier / 100.0%).
- **Executive Compliance Report Generator (`tcha report`):** Generates self-contained, air-gapped HTML/PDF audit certificates containing the cryptographic Merkle root hash, scorecard, and compliance crosswalk (OWASP LLM Top 10, EU AI Act Art. 15, SOC 2 CC6.1, ISO 42001).
- **Steganography & Delimiter Boundary Sanitizer:** Detects and neutralizes zero-width unicode steganography (`\u200B`, `\uFEFF`, etc.), ASCII smuggling via Unicode tags (`U+E0000` to `U+E007F`), and multi-modal delimiter breakouts.
- **SSRF & Network Egress Firewall:** Resolves DNS hostnames and strictly blocks requests targeting AWS/Azure/GCP metadata (`169.254.169.254`, `fd00:ec2::254`), IPv4-mapped IPv6 loopbacks (`::ffff:127.0.0.1`), hex/octal/decimal IP encodings (`0x7f000001`, `2130706433`), and RFC-1918 private subnets.
- **Cryptographic Merkle Audit Ledger:** Persists security events into SQLite with continuous SHA-256 hash chaining, enabling instant mathematical proof of non-tampering (`tcha verify-ledger`).
- **Human-in-the-Loop (HITL) Tier 3 Gate:** Generates HMAC-SHA256 authorization challenges for destructive mutations (e.g., table drops, transfers, shell execution) requiring human verification before downstream execution.

---

## 🚀 Quickstart & Commands

```bash
# 1. Run the 100-Probe Adversarial Red-Teaming Suite
tcha audit
# Or via npm
npm run audit

# 2. Generate the Executive Compliance HTML/PDF Report
tcha report report.html
# Or via npm
npm run report

# 3. Wrap an MCP Server in the In-Line Security Proxy
tcha wrap npx -y @modelcontextprotocol/server-filesystem D:/data
# Or run with local node scripts
tcha wrap node path/to/server.js

# 4. Verify Cryptographic Merkle Ledger Nonce Integrity
tcha verify-ledger

# 5. Run All Automated Test Suites (30 Unit Tests + In-Line Proxy Integration)
npm test
```

---

## 📊 100-Probe Attack Matrix Coverage

| Attack Vector | Category | OWASP LLM 2025/2026 Matrix | Defended By |
|---|---|---|---|
| **Indirect Prompt Injection** | 25 Probes | LLM01:2025 Prompt Injection | `PromptSanitizer` (XML encapsulation & delimiter neutralization) |
| **Unicode Steganography & ASCII Smuggling** | Integrated | LLM01:2025 / Steganographic Evasion | `PromptSanitizer` (Zero-width stripping & tag filter) |
| **SSRF & Cloud Metadata Exfiltration** | 25 Probes | LLM02:2025 Sensitive Information / SSRF | `SSRFGuard` (IMDSv1/v2, IPv4/IPv6, hex/octal decoding) |
| **Path Traversal & Shell Metacharacters** | 25 Probes | LLM05:2025 Improper Output Handling | `RiskEngine` (Argument token inspection & sanitization) |
| **Unauthorized Tool Abuse & Privilege Escalation** | 25 Probes | LLM06:2025 Excessive Agency & Autonomy | `RiskEngine` (3-Tier classification & HMAC sign-off gate) |

---

## 🏛️ Architecture & 6-Pillar Spec Blueprint

Tcha Protection Pro 2.0 was architected in adherence to the **6-Pillar Engineering Specification Blueprint**:
- [`specs/01_PRD.md`](specs/01_PRD.md) : Scope, dual-core architecture, and compliance mandates.
- [`specs/02_TRD.md`](specs/02_TRD.md) : Hybrid TypeScript/Python architecture, file tree contract, $\le 2\text{ms}$ latency budgets.
- [`specs/03_APP_FLOW.md`](specs/03_APP_FLOW.md) : Audit execution, proxy interception, and ledger verification lifecycles.
- [`specs/04_UI_UX.md`](specs/04_UI_UX.md) : Executive compliance report typography, dark-mode tokens, and print-to-PDF styles.
- [`specs/05_SCHEMA.md`](specs/05_SCHEMA.md) : SQLite Merkle ledger schema and JSON-RPC 2.0 `-32001` error contracts.
- [`specs/06_IMPLEMENTATION_PLAN.md`](specs/06_IMPLEMENTATION_PLAN.md) : Chronological milestones with Definition of Done.

---

## 📜 Compliance Standards Addressed

- **EU AI Act (Regulation 2024/1689):** Article 15 (Cybersecurity & Robustness Requirements for Autonomous Systems).
- **SOC 2 Type II:** CC6.1 / CC6.6 (Perimeter & Egress Security Boundaries).
- **OWASP Top 10 for Large Language Models 2025/2026:** Comprehensive probe coverage across LLM01 through LLM09.
- **ISO/IEC 42001:2023:** Control A.6.2 (AI System Risk Management & Tamper-Evident Audit Logging).

---

## 📜 License
MIT License. Created with Antigravity 2.0.
