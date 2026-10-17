# 04. UI / UX Design & Reporting Specification — AgentShield Pro 2.0

## 1. Aesthetic Direction & Visual Language

AgentShield Pro follows a **Cyber-Defensive Precision & Modern Executive Editorial** aesthetic:
* **Dark Mode Core:** Backgrounds in `#0B0C0E` and `#111317` with hairline `#1F242D` borders.
* **Accent Colors:**
  * Emerald Shield (Pass / Secure): `#10B981` (Backgrounds: `rgba(16, 185, 129, 0.1)`)
  * Crimson Threat (Blocked / Critical): `#EF4444` (Backgrounds: `rgba(239, 68, 68, 0.1)`)
  * Amber Warning (HITL Challenge / Pending): `#F59E0B`
  * Electric Cyan (Merkle Cryptography & Verification): `#06B6D4`
* **Typography:**
  * Headings: Uncompromising geometric sans-serif (Inter, SF Pro Display, or system-ui).
  * Hashes & Data: High-legibility monospaced font (JetBrains Mono, SF Mono, Menlo).

---

## 2. Executive Audit Report Template Specifications (`report.html`)

The generated audit report is the primary **commercial artifact** that justifies enterprise pricing. It must look executive-grade and print seamlessly to PDF:

```
+-----------------------------------------------------------------------------------------+
|  🛡️ AGENTSHIELD PRO — AI AGENT CYBERSECURITY AUDIT CERTIFICATE                         |
+-----------------------------------------------------------------------------------------+
| Target: Production Financial Agent (MCP Suite v2.4)     Date: 2026-10-17 03:15 UTC       |
| Merkle Root: 8f9b2c...a47e (Cryptographically Verified) Status: PASSED (100.0%)         |
+-----------------------------------------------------------------------------------------+
|                                                                                         |
|   +-------------------+    +--------------------------------------------------------+   |
|   |   OVERALL SCORE   |    |                   ATTACK VECTOR BREAKDOWN              |   |
|   |                   |    |                                                        |   |
|   |       A+          |    | Prompt Injections (25/25)        [===================] |   |
|   |     (100.0%)      |    | SSRF & Network Egress (25/25)    [===================] |   |
|   |                   |    | Traversal & Shell (15/15)        [===================] |   |
|   | 100/100 Probes    |    | Steganography & Encodings (15/15)[===================] |   |
|   |   Neutralized     |    | Tool Privilege Escalations (20/20)[==================] |   |
|   +-------------------+    +--------------------------------------------------------+   |
|                                                                                         |
| COMPLIANCE CROSSWALK:                                                                   |
| [x] OWASP Top 10 for LLMs (2025/2026 Ready)    [x] EU AI Act Article 15 (Robustness)    |
| [x] SOC2 Type II Audit Artifact Attached       [x] ISO/IEC 42001 AI Risk Management     |
+-----------------------------------------------------------------------------------------+
| DETAILED PROBE EVIDENCE LOG (100 Items, Expandable, Filterable)                         |
+-----------------------------------------------------------------------------------------+
```

### Self-Contained Zero-Dependency Rule
The report template must embed all styles and SVG icons inline:
* **Zero external network calls** (works 100% offline and in air-gapped security enclaves).
* **Print Stylesheet (`@media print`):** Automatically converts dark backgrounds to crisp white paper layout for boardroom/auditor distribution.
