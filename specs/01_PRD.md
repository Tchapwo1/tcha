# 01. Product Requirement Document (PRD) — AgentShield Pro 2.0

## 1. Vision & Purpose

**AgentShield Pro** is an enterprise-grade AI agent security suite, automated red-teaming platform, and in-line MCP (Model Context Protocol) firewall. It bridges the critical security gap created by autonomous AI agents and MCP tools: preventing indirect prompt injections, blocking SSRF egress against internal networks and cloud metadata, enforcing Human-in-the-Loop (HITL) authorization on destructive tool executions, and generating auditor-ready security compliance reports (aligned with OWASP Top 10 for LLMs 2025/2026, EU AI Act, and SOC2).

In 2026, organizations are deploying autonomous AI agents directly connected to filesystems, command-line interfaces, databases, and third-party SaaS APIs. A single untrusted prompt injection can manipulate an agent into deleting infrastructure, exfiltrating credentials, or bypassing auth boundaries. **AgentShield Pro** provides the **Dual-Core Solution**:
1. **The Pre-Deployment Auditor:** 100 automated adversarial attack probes generating cryptographic compliance reports.
2. **The In-Line MCP Proxy:** A zero-latency, drop-in STDIO/SSE reverse proxy intercepting and neutralizing unauthorized tool calls in real time.

---

## 2. Target Personas & Commercial Use Cases

1. **Enterprise AI & DevSecOps Teams:** Need continuous CI/CD red-teaming and compliance audit artifacts to prove to security boards and auditors that agents cannot be compromised.
2. **AI Startup Founders & CTOs:** Need an instant, one-command penetration test report (`agentshield audit`) to close enterprise deals requiring third-party AI safety verification.
3. **Autonomous Agent Builders (Claude Code, Cursor, Antigravity, AutoGen):** Need a local, transparent in-line proxy that prevents agents from running destructive commands while working autonomously.

---

## 3. Commercial Model & Packaging

* **Open-Core CLI (Free):** 50-probe baseline audit (`agentshield audit`), local SQLite Merkle ledger, and basic prompt sanitization.
* **AgentShield Pro (£999 / Audit or £199 / Month):**
  * 100-probe comprehensive red-teaming suite (ASCII smuggling, zero-width steganography, memory poisoning, multi-modal prompt leak).
  * Executive Audit Report Generator (dark-mode HTML & printable PDF compliance certification with cryptographic Merkle proof).
  * In-Line MCP STDIO Proxy (`agentshield wrap <mcp-command>`) with dynamic argument inspection and real-time HITL authorization.
  * CI/CD GitHub Action integration for blocking vulnerable agent PRs.

---

## 4. Core Features & Functional Scope

### Feature 1: The 100-Probe Adversarial Red-Teaming Engine
* **Description:** An expanded, deterministic test harness firing 100 attack probes across 5 critical vectors:
  1. *Prompt Injections & Jailbreaks (25 probes):* Delimiter breakouts, roleplay overrides, instruction hijacking.
  2. *Steganographic & Encoding Evasion (15 probes):* ASCII smuggling, zero-width unicode injection, Base64/Rot13 polyglot payloads.
  3. *SSRF & Network Egress (25 probes):* Cloud metadata (`169.254.169.254`), RFC-1918 subnets, `file://`, `dict://`, `gopher://`.
  4. *Path Traversal & Command Injection (15 probes):* `../../`, double-dot URL encoding, shell chaining (`&&`, `;`, `|`), environment variable dumping.
  5. *Tool Privilege & HITL Escalation (20 probes):* Destructive database operations, unauthorized financial transfers, process killing, audit log tampering.
* **Success Criteria:** Executes all 100 probes in under 45 seconds; outputs granular scorecards with pass/fail and remediation advice.

### Feature 2: Executive Compliance Report Generator
* **Description:** Automatically compiles audit findings into a museum-grade, dark-mode HTML and Markdown report (printable to PDF) featuring:
  * Executive Summary with letter grade (A+ through F) and Resilience Percentage.
  * Attack vector distribution breakdown (polar/bar telemetry).
  * Cryptographic Merkle Root Hash certifying the audit run is tamper-evident.
  * Detailed vulnerability findings with remediation steps.
* **Success Criteria:** Single command (`agentshield audit --export report.html`) creates an executive report in under 2 seconds.

### Feature 3: In-Line MCP STDIO Reverse Proxy (`agentshield wrap`)
* **Description:** A transparent reverse proxy that wraps any standard MCP server command:
  ```bash
  agentshield wrap -- npx -y @modelcontextprotocol/server-filesystem D:/workspace
  ```
  * Intercepts `tools/call` JSON-RPC messages before they execute on the host.
  * Evaluates arguments through the SSRF Guard, Path Traversal Filter, and Risk Engine.
  * Passes Tier 1 (read-only) tools with $< 2\text{ms}$ latency overhead.
  * Pauses Tier 3 (destructive) tools, dispatching an HMAC-signed challenge token requiring human confirmation.
* **Success Criteria:** 100% transparent passthrough of valid tools with zero disruption to streaming responses.

### Feature 4: Cryptographic Merkle Ledger & Integrity Verification
* **Description:** Append-only SQLite ledger chaining every event into a SHA-256 Merkle tree.
* **Success Criteria:** `agentshield verify-ledger` validates the entire hash chain in $< 500\text{ms}$.

---

## 5. Strict Out-of-Scope Boundaries (Anti-Scope Creep)

1. **NO Heavy Local LLM Hosting:** Does not package or run local 20GB models. Works purely as a protocol-level proxy and security scanner.
2. **NO Proprietary SaaS Dependency:** All auditing and proxying runs 100% locally or within the customer's self-hosted CI/CD pipeline.
3. **NO Invasive Code Modifications:** Does not alter customer agent code; wraps standard MCP STDIO interfaces.
