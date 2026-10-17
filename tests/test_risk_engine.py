import pytest
import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from core.risk_engine import RiskEngine, ToolRiskTier

def test_classify_tier_1_read_only():
    """Verify read-only tools are assigned to Tier 1."""
    tools = ["read_file", "search_web", "list_directory", "inspect_ast", "get_weather"]
    for t in tools:
        tier, reason = RiskEngine.classify_tool(t)
        assert tier == ToolRiskTier.TIER_1_READ_ONLY

def test_classify_tier_3_destructive():
    """Verify destructive and shell tools are assigned to Tier 3."""
    tools = ["exec_bash", "delete_database", "run_shell_command", "drop_table", "transfer_funds"]
    for t in tools:
        tier, reason = RiskEngine.classify_tool(t)
        assert tier == ToolRiskTier.TIER_3_DESTRUCTIVE

def test_classify_tier_2_mutating():
    """Verify standard mutating actions fall into Tier 2."""
    tools = ["post_slack", "create_issue", "update_metadata"]
    for t in tools:
        tier, reason = RiskEngine.classify_tool(t)
        assert tier == ToolRiskTier.TIER_2_MUTATING

def test_hitl_challenge_generation_and_verification():
    """Verify HMAC-SHA256 signature generation and validation."""
    challenge = RiskEngine.generate_hitl_challenge(
        tool_name="delete_database",
        params={"db_name": "production_users"},
        ttl_seconds=60
    )
    
    assert challenge["tool_name"] == "delete_database"
    assert challenge["status"] == "PENDING_APPROVAL"
    assert len(challenge["approval_token"]) == 64 # SHA-256 hex length

    # Valid verification
    valid, msg = RiskEngine.verify_hitl_approval(
        challenge["challenge_payload"],
        challenge["approval_token"]
    )
    assert valid is True
    assert "cryptographically valid" in msg

    # Invalid token rejected
    bad_token = "0" * 64
    valid, msg = RiskEngine.verify_hitl_approval(
        challenge["challenge_payload"],
        bad_token
    )
    assert valid is False
    assert "Invalid signature" in msg

def test_hitl_token_expiration():
    """Verify that expired tokens are strictly rejected."""
    # Create challenge with negative TTL (already expired)
    challenge = RiskEngine.generate_hitl_challenge(
        tool_name="delete_file",
        params={"path": "/important.txt"},
        ttl_seconds=-10
    )
    valid, msg = RiskEngine.verify_hitl_approval(
        challenge["challenge_payload"],
        challenge["approval_token"]
    )
    assert valid is False
    assert "expired" in msg
