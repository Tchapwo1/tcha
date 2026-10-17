"""
AgentShield Tool Risk Engine & HITL Authorization Gate
Classifies MCP tools into 3 distinct operational risk tiers and generates
cryptographic HMAC-SHA256 tokens for destructive actions requiring human sign-off.
"""

import hmac
import hashlib
import time
from typing import Dict, Any, Tuple

DEFAULT_SECRET_KEY = b"agentshield_local_dev_secret_key_994821"

TIER_3_DESTRUCTIVE_KEYWORDS = {
    "delete", "remove", "drop", "destroy", "truncate", "purge", "erase",
    "bash", "sh", "exec", "shell", "eval", "sudo", "kill", "spawn", "powershell",
    "transfer", "pay", "charge", "refund", "purchase", "modify_payroll",
    "grant_admin", "disable_firewall", "reset_mfa", "rotate_root", "bypass_auth",
    "overwrite_agent_memory", "poison", "corrupt", "inject_rag"
}

TIER_1_READ_ONLY_KEYWORDS = {
    "read", "get", "fetch", "list", "search", "inspect", "view",
    "check", "scan", "status", "count", "metrics", "find"
}

class ToolRiskTier:
    TIER_1_READ_ONLY = "TIER_1_READ_ONLY"         # Safe: auto-approved
    TIER_2_MUTATING = "TIER_2_MUTATING"           # State-changing: logged with idempotency key
    TIER_3_DESTRUCTIVE = "TIER_3_DESTRUCTIVE"     # High-risk: requires Human-in-the-Loop approval

class RiskEngine:
    @staticmethod
    def inspect_argument_payload(params: Dict[str, Any]) -> Tuple[bool, str]:
        """Checks if tool parameters contain path traversal or shell metacharacter injections."""
        if not params:
            return False, ""
        
        suspicious_tokens = [";", "|", "$(", "`", "..", "&&", "&", "%2e%2e", "%2f", "%5c"]
        for key, val in params.items():
            str_val = str(val)
            for tok in suspicious_tokens:
                if tok in str_val:
                    return True, f"Suspicious token '{tok}' found in argument '{key}'"
        return False, ""

    @classmethod
    def classify_tool(cls, tool_name: str, params: Dict[str, Any] = None) -> Tuple[str, str]:
        """
        Classifies an MCP tool name and arguments into Tier 1, 2, or 3.
        Returns: (Tier, Rationale)
        """
        lower_name = tool_name.lower()

        # Check Tier 3 (Destructive / High-Risk by name)
        for kw in TIER_3_DESTRUCTIVE_KEYWORDS:
            if kw in lower_name:
                return (
                    ToolRiskTier.TIER_3_DESTRUCTIVE,
                    f"Tool name '{tool_name}' contains destructive, privilege escalation, or shell keyword '{kw}'."
                )

        # Check parameters for path traversal / shell chaining injection
        if params:
            has_injection, reason = cls.inspect_argument_payload(params)
            if has_injection:
                return (
                    ToolRiskTier.TIER_3_DESTRUCTIVE,
                    f"Tool invocation '{tool_name}' contains potentially dangerous parameter sequence: {reason}."
                )

        # Check Tier 1 (Read-Only)
        for kw in TIER_1_READ_ONLY_KEYWORDS:
            if kw in lower_name:
                return (
                    ToolRiskTier.TIER_1_READ_ONLY,
                    f"Tool name '{tool_name}' is recognized as safe read-only query ('{kw}')."
                )

        # Default to Tier 2 (Mutating / Moderate Risk)
        return (
            ToolRiskTier.TIER_2_MUTATING,
            f"Tool name '{tool_name}' mutates state and requires standard idempotency logging."
        )

    @staticmethod
    def generate_hitl_challenge(
        tool_name: str,
        params: Dict[str, Any],
        secret_key: bytes = DEFAULT_SECRET_KEY,
        ttl_seconds: int = 300
    ) -> Dict[str, Any]:
        """Generates a signed HMAC-SHA256 challenge for a pending human approval."""
        timestamp = int(time.time())
        expires_at = timestamp + ttl_seconds
        
        # Canonical representation of params
        sorted_params = str(sorted(params.items())) if params else ""
        challenge_payload = f"{tool_name}:{sorted_params}:{expires_at}"
        
        token = hmac.new(secret_key, challenge_payload.encode("utf-8"), hashlib.sha256).hexdigest()

        return {
            "tool_name": tool_name,
            "params": params,
            "created_at": timestamp,
            "expires_at": expires_at,
            "approval_token": token,
            "challenge_payload": challenge_payload,
            "status": "PENDING_APPROVAL"
        }

    @staticmethod
    def verify_hitl_approval(
        challenge_payload: str,
        provided_token: str,
        secret_key: bytes = DEFAULT_SECRET_KEY
    ) -> Tuple[bool, str]:
        """Validates that an approval token is mathematically authentic and unexpired."""
        try:
            parts = challenge_payload.split(":")
            expires_at = int(parts[-1])
            
            if time.time() > expires_at:
                return False, "Approval token has expired. Request a new challenge."

            expected_token = hmac.new(secret_key, challenge_payload.encode("utf-8"), hashlib.sha256).hexdigest()
            if hmac.compare_digest(expected_token, provided_token):
                return True, "Authorization token is cryptographically valid."
            else:
                return False, "Invalid signature: token does not match expected HMAC signature."
        except Exception as e:
            return False, f"Token verification error: {e}"
