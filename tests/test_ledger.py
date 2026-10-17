import pytest
import sqlite3
import sys
import os
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from core.ledger import SecurityLedger

@pytest.fixture
def temp_ledger():
    """Provides a temporary, isolated SQLite ledger for testing."""
    temp_dir = tempfile.mkdtemp()
    temp_path = os.path.join(temp_dir, "test_ledger.db")
    ledger = SecurityLedger(db_path=temp_path)
    yield ledger
    # Ensure any pending sqlite resources are finalized
    import gc
    gc.collect()
    try:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        os.rmdir(temp_dir)
    except Exception:
        pass

def test_empty_ledger_is_valid(temp_ledger):
    """An empty ledger must return valid integrity with count 0."""
    valid, msg, count = temp_ledger.verify_integrity()
    assert valid is True
    assert count == 0

def test_record_events_and_verify_chain(temp_ledger):
    """Record multiple events and verify that the Merkle hash chain is intact."""
    evt1 = temp_ledger.record_event(
        event_type="TOOL_CALL",
        severity="INFO",
        target_tool="read_file",
        source_agent="agent_alpha",
        raw_payload='{"path": "README.md"}',
        sanitized_payload='{"path": "README.md"}',
        action_taken="ALLOWED"
    )
    assert evt1["prev_hash"] == "0" * 64

    evt2 = temp_ledger.record_event(
        event_type="SSRF_ATTEMPT",
        severity="CRITICAL",
        target_tool="fetch_url",
        source_agent="agent_alpha",
        raw_payload='{"url": "http://169.254.169.254/"}',
        sanitized_payload="",
        action_taken="BLOCKED"
    )
    # Event 2's prev_hash must strictly match Event 1's merkle_hash
    assert evt2["prev_hash"] == evt1["merkle_hash"]

    valid, msg, count = temp_ledger.verify_integrity()
    assert valid is True
    assert count == 2

def test_tamper_detection(temp_ledger):
    """Manually altering an event payload in SQLite must cause integrity verification to fail."""
    temp_ledger.record_event(
        event_type="TOOL_CALL",
        severity="INFO",
        target_tool="read_file",
        source_agent="agent_alpha",
        raw_payload='{"path": "safe.txt"}',
        sanitized_payload="",
        action_taken="ALLOWED"
    )
    
    # Tamper with the raw_payload directly in the DB
    with sqlite3.connect(temp_ledger.db_path) as conn:
        conn.execute("UPDATE security_events SET raw_payload = '{\"path\": \"TAMPERED.txt\"}'")
        conn.commit()

    valid, msg, count = temp_ledger.verify_integrity()
    assert valid is False
    assert "Tampered record" in msg

def test_canary_token_generation_and_detection(temp_ledger):
    """Verify canary creation and detection in untrusted text."""
    canary = temp_ledger.generate_canary("Secret System API Key")
    assert canary.startswith("CANARY_")

    clean_text = "This is a normal paragraph with no secrets."
    assert len(temp_ledger.check_for_canaries(clean_text)) == 0

    leaked_text = f"Here is the exfiltrated key: {canary} from the agent."
    triggered = temp_ledger.check_for_canaries(leaked_text)
    assert len(triggered) == 1
    assert triggered[0]["token_string"] == canary
