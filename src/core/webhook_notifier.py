"""
AgentShield Webhook Notifier (Python)
Asynchronous non-blocking alerting for Slack, Discord, and Generic SIEM webhooks.
"""

import os
import time
import json
import hmac
import hashlib
import urllib.request
import urllib.error
from typing import Dict, Any, Optional, Tuple

class WebhookNotifier:
    _recent_alerts: Dict[str, float] = {}
    _dedup_window_s: float = 60.0

    @classmethod
    def detect_provider(cls, url: str) -> str:
        lower = url.lower()
        if "hooks.slack.com" in lower or "slack.com/services" in lower:
            return "slack"
        if "discord.com/api/webhooks" in lower or "discordapp.com/api/webhooks" in lower:
            return "discord"
        return "generic"

    @classmethod
    def format_slack(cls, event: Dict[str, Any]) -> Dict[str, Any]:
        is_critical = event.get("severity") == "CRITICAL" or event.get("actionTaken") == "BLOCKED"
        emoji = "🚨" if is_critical else "⚠️" if event.get("severity") == "HIGH" else "🛡️"
        color = "#ef4444" if is_critical else "#f59e0b" if event.get("severity") == "HIGH" else "#10b981"

        return {
            "text": f"{emoji} [AgentShield Security Alert]: {event.get('eventType')} on `{event.get('targetTool')}`",
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"{emoji} AgentShield: {event.get('eventType')}",
                                "emoji": True
                            }
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": f"*Severity:*\n`{event.get('severity')}`"},
                                {"type": "mrkdwn", "text": f"*Action Taken:*\n`{event.get('actionTaken')}`"},
                                {"type": "mrkdwn", "text": f"*Target Tool:*\n`{event.get('targetTool')}`"},
                                {"type": "mrkdwn", "text": f"*Source Agent:*\n`{event.get('sourceAgent', 'agent_client')}`"}
                            ]
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"*Payload Snippet:*\n```{str(event.get('rawPayload', '{}'))[:300]}```"
                            }
                        }
                    ]
                }
            ]
        }

    @classmethod
    def format_discord(cls, event: Dict[str, Any]) -> Dict[str, Any]:
        is_critical = event.get("severity") == "CRITICAL" or event.get("actionTaken") == "BLOCKED"
        color = 0xef4444 if is_critical else 0xf59e0b if event.get("severity") == "HIGH" else 0x10b981

        return {
            "username": "AgentShield Security Gateway",
            "embeds": [
                {
                    "title": f"🛡️ Security Alert: {event.get('eventType')}",
                    "description": "An intercepted tool invocation required automated defensive mitigation.",
                    "color": color,
                    "fields": [
                        {"name": "Target Tool", "value": f"`{event.get('targetTool')}`", "inline": True},
                        {"name": "Action Taken", "value": f"**{event.get('actionTaken')}**", "inline": True},
                        {"name": "Severity", "value": f"`{event.get('severity')}`", "inline": True},
                        {
                            "name": "Intercepted Payload",
                            "value": f"```json\n{str(event.get('rawPayload', '{}'))[:500]}\n```",
                            "inline": False
                        }
                    ],
                    "footer": {
                        "text": "AgentShield v1.1.0 • Cryptographic Merkle Ledger Active"
                    }
                }
            ]
        }

    @classmethod
    def format_generic(cls, event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "agentShieldAlert": True,
            "version": "1.1.0",
            "timestamp": event.get("timestamp", int(time.time() * 1000)),
            "event": event
        }

    @classmethod
    def dispatch(cls, event: Dict[str, Any], url: Optional[str] = None, secret: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        target_url = url or os.environ.get("AGENTSHIELD_WEBHOOK_URL")
        if not target_url:
            return False, "No webhook URL configured."

        # Deduplication
        dedup_key = f"{event.get('eventType')}:{event.get('targetTool')}:{str(event.get('rawPayload', ''))[:50]}"
        now = time.time()
        last_seen = cls._recent_alerts.get(dedup_key, 0.0)

        if not url and (now - last_seen < cls._dedup_window_s):
            return True, "Deduplicated"

        cls._recent_alerts[dedup_key] = now

        provider = cls.detect_provider(target_url)
        if provider == "slack":
            body_dict = cls.format_slack(event)
        elif provider == "discord":
            body_dict = cls.format_discord(event)
        else:
            body_dict = cls.format_generic(event)

        body_bytes = json.dumps(body_dict).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "AgentShield-Security-Gateway/1.1.0"
        }

        signing_secret = secret or os.environ.get("AGENTSHIELD_WEBHOOK_SECRET")
        if signing_secret:
            sig = hmac.new(signing_secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
            headers["X-AgentShield-Signature"] = f"sha256={sig}"

        req = urllib.request.Request(target_url, data=body_bytes, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                success = 200 <= resp.status < 300
                return success, None if success else f"HTTP {resp.status}"
        except urllib.error.HTTPError as e:
            return False, f"HTTPError {e.code}"
        except Exception as e:
            return False, str(e)
