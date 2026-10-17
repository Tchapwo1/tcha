import pytest
import sys
import os

# Add src to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from core.ssrf_guard import SSRFGuard, SSRFSecurityViolation

def test_block_cloud_metadata():
    """Verify that AWS/Azure/GCP instance metadata endpoint 169.254.169.254 is strictly blocked."""
    url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    safe, reason = SSRFGuard.is_safe_url(url)
    assert safe is False
    assert "169.254.0.0/16" in reason or "forbidden range" in reason

    with pytest.raises(SSRFSecurityViolation):
        SSRFGuard.assert_safe_url(url)

def test_block_loopback_ipv4():
    """Verify that localhost/127.0.0.1 is blocked."""
    url = "http://127.0.0.1:8080/admin"
    safe, reason = SSRFGuard.is_safe_url(url)
    assert safe is False
    assert "127.0.0.0/8" in reason or "forbidden range" in reason

def test_block_rfc1918_private_ranges():
    """Verify that standard private corporate networks are blocked."""
    private_urls = [
        "http://10.0.0.5/api/keys",
        "http://192.168.1.1/router-login",
        "http://172.16.50.2/internal-db"
    ]
    for u in private_urls:
        safe, reason = SSRFGuard.is_safe_url(u)
        assert safe is False, f"Expected {u} to be blocked, but was marked safe."

def test_allow_public_safe_urls():
    """Verify that valid public internet URLs pass safety inspection."""
    public_urls = [
        "https://example.com/api/data",
        "https://api.github.com/repos"
    ]
    for u in public_urls:
        safe, reason = SSRFGuard.is_safe_url(u)
        assert safe is True, f"Expected {u} to be safe, reason: {reason}"

def test_reject_invalid_schemes():
    """Verify that non-HTTP schemes (file://, gopher://, dict://) are rejected."""
    bad_schemes = [
        "file:///etc/passwd",
        "gopher://127.0.0.1:70/",
        "ftp://internal.server/data"
    ]
    for u in bad_schemes:
        safe, reason = SSRFGuard.is_safe_url(u)
        assert safe is False
        assert "Unsupported URL scheme" in reason
