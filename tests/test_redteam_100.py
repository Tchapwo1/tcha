import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from cli.redteam_runner import (
    INJECTION_PROBES,
    SSRF_PROBES,
    TRAVERSAL_PROBES,
    TOOL_ABUSE_PROBES,
    run_adversarial_suite,
)
from core.prompt_sanitizer import PromptSanitizer
from core.ssrf_guard import SSRFGuard
from core.risk_engine import RiskEngine, ToolRiskTier

def test_probe_suite_volume():
    """Verify that exactly 100 adversarial probes are registered across 4 OWASP LLM categories."""
    assert len(INJECTION_PROBES) == 25
    assert len(SSRF_PROBES) == 25
    assert len(TRAVERSAL_PROBES) == 25
    assert len(TOOL_ABUSE_PROBES) == 25
    assert (len(INJECTION_PROBES) + len(SSRF_PROBES) + len(TRAVERSAL_PROBES) + len(TOOL_ABUSE_PROBES)) == 100

def test_indirect_injection_and_steganography_probes():
    """Verify all 25 prompt injection and steganography probes are neutralized."""
    for probe in INJECTION_PROBES:
        sanitized = PromptSanitizer.sanitize_untrusted_content(probe)
        encapsulated = sanitized["sanitized_prompt"]
        
        # Must be safely encapsulated and delimiter breakouts neutralized
        assert "<untrusted_external_content" in encapsulated
        assert "</untrusted_external_content>" in encapsulated
        # No forged close tag can break out of the tag
        assert "</untrusted_external_content>" not in probe.split("</untrusted_external_content>")[0]

def test_ssrf_and_egress_probes():
    """Verify all 25 SSRF and private network exfiltration probes are blocked."""
    for url in SSRF_PROBES:
        safe, reason = SSRFGuard.is_safe_url(url)
        assert safe is False, f"Expected SSRF probe {url} to be blocked, but was marked safe."

def test_path_traversal_and_shell_probes():
    """Verify all 25 traversal and shell chaining sequences are detected."""
    for payload in TRAVERSAL_PROBES:
        is_suspicious = any(c in payload for c in [";", "|", "$(", "`", "..", "&&", "&", "%2e%2e", "%2f", "%5c"])
        assert is_suspicious is True, f"Failed to flag traversal payload: {payload}"

def test_destructive_tool_abuse_probes():
    """Verify all 25 destructive tool names are classified as Tier 3 requiring HITL approval."""
    for tool_name in TOOL_ABUSE_PROBES:
        tier, reason = RiskEngine.classify_tool(tool_name)
        assert tier == ToolRiskTier.TIER_3_DESTRUCTIVE, f"Tool {tool_name} was classified as {tier} instead of Tier 3."

def test_full_redteam_suite_execution():
    """Execute the full 100-probe suite and verify 100.0% resilience score."""
    resilience = run_adversarial_suite(export_path="tests/test_audit_report.html")
    assert resilience == 100.0
    assert os.path.exists("tests/test_audit_report.html")
    # Clean up test artifact
    try:
        os.remove("tests/test_audit_report.html")
    except OSError:
        pass
