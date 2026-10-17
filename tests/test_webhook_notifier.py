import pytest
import sys
import os

# Add src to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from unittest.mock import patch, MagicMock
from core.webhook_notifier import WebhookNotifier

def test_provider_detection():
    slack_url = "https://hooks.slack.com/services/sample-team/sample-channel/dummy-test-webhook"
    discord_url = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz"
    generic_url = "https://siem.mycompany.internal/api/v1/agent-alerts"

    assert WebhookNotifier.detect_provider(slack_url) == "slack"
    assert WebhookNotifier.detect_provider(discord_url) == "discord"
    assert WebhookNotifier.detect_provider(generic_url) == "generic"

def test_slack_formatting():
    event = {
        "eventType": "SSRF_ATTEMPT",
        "severity": "CRITICAL",
        "targetTool": "fetch_url",
        "sourceAgent": "browser_agent",
        "rawPayload": '{"url":"http://169.254.169.254/meta"}',
        "actionTaken": "BLOCKED"
    }

    slack_data = WebhookNotifier.format_slack(event)
    assert "🚨" in slack_data["text"]
    assert "attachments" in slack_data
    blocks = slack_data["attachments"][0]["blocks"]
    assert blocks[0]["type"] == "header"
    assert "AgentShield: SSRF_ATTEMPT" in blocks[0]["text"]["text"]

def test_discord_formatting():
    event = {
        "eventType": "HITL_PROMPT",
        "severity": "HIGH",
        "targetTool": "execute_sql_drop",
        "sourceAgent": "db_agent",
        "rawPayload": '{"query":"DROP TABLE users"}',
        "actionTaken": "SUSPENDED_HITL"
    }

    discord_data = WebhookNotifier.format_discord(event)
    assert "embeds" in discord_data
    embed = discord_data["embeds"][0]
    assert embed["color"] == 0xf59e0b # Warning yellow
    assert "Target Tool" in [f["name"] for f in embed["fields"]]
    assert "**SUSPENDED_HITL**" in [f["value"] for f in embed["fields"]]

def test_generic_formatting():
    event = {
        "eventType": "PROMPT_INJECTION",
        "severity": "HIGH",
        "targetTool": "ingest_web",
        "actionTaken": "SANITIZED"
    }

    generic_data = WebhookNotifier.format_generic(event)
    assert generic_data["agentShieldAlert"] is True
    assert generic_data["version"] == "1.1.0"
    assert generic_data["event"]["actionTaken"] == "SANITIZED"

@patch("urllib.request.urlopen")
def test_dispatch_slack_mocked(mock_urlopen):
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    event = {
        "eventType": "SSRF_ATTEMPT",
        "severity": "CRITICAL",
        "targetTool": "fetch_url",
        "rawPayload": "test_unique_payload_123",
        "actionTaken": "BLOCKED"
    }

    url = "https://hooks.slack.com/services/mock/token/abc"
    success, err = WebhookNotifier.dispatch(event, url=url)
    assert success is True
    assert err is None
    assert mock_urlopen.called

def test_dispatch_no_url():
    event = {"eventType": "TEST", "severity": "INFO"}
    with patch.dict("os.environ", {}, clear=True):
        success, err = WebhookNotifier.dispatch(event, url=None)
        assert success is False
        assert "No webhook URL configured" in err
