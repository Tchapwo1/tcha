"""
AgentShield Tamper-Evident Merkle Audit Ledger
Records security events and canary tokens in SQLite with continuous SHA-256 hash chaining.
"""

import sqlite3
import hashlib
import time
import uuid
import json
from typing import Dict, Any, List, Optional, Tuple

class SecurityLedger:
    def __init__(self, db_path: str = "agentshield.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS security_events (
                id TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                target_tool TEXT NOT NULL,
                source_agent TEXT NOT NULL,
                raw_payload TEXT,
                sanitized_payload TEXT,
                action_taken TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                merkle_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS canary_tokens (
                token_id TEXT PRIMARY KEY,
                token_string TEXT NOT NULL UNIQUE,
                label TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                trigger_count INTEGER NOT NULL DEFAULT 0,
                last_triggered_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS audit_runs (
                audit_id TEXT PRIMARY KEY,
                started_at INTEGER NOT NULL,
                completed_at INTEGER NOT NULL,
                target_endpoint TEXT NOT NULL,
                total_probes INTEGER NOT NULL DEFAULT 50,
                passed_probes INTEGER NOT NULL DEFAULT 0,
                failed_probes INTEGER NOT NULL DEFAULT 0,
                resilience_score REAL NOT NULL,
                report_json TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)

    def get_latest_hash(self) -> str:
        """Retrieves the Merkle hash of the latest event or genesis hash if empty."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT merkle_hash FROM security_events ORDER BY rowid DESC LIMIT 1")
            row = cursor.fetchone()
            return row[0] if row else "0" * 64

    def record_event(
        self,
        event_type: str,
        severity: str,
        target_tool: str,
        source_agent: str,
        raw_payload: str,
        sanitized_payload: str,
        action_taken: str,
        event_id: Optional[str] = None,
        timestamp: Optional[int] = None
    ) -> Dict[str, Any]:
        """Atomically appends a new event and updates the Merkle chain."""
        evt_id = event_id or str(uuid.uuid4())
        ts = timestamp if timestamp is not None else int(time.time() * 1000)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT merkle_hash FROM security_events ORDER BY rowid DESC LIMIT 1")
            row = cursor.fetchone()
            prev_hash = row[0] if row else "0" * 64

            # Merkle Hash Formula
            payload_str = raw_payload or ""
            hash_input = f"{prev_hash}:{evt_id}:{ts}:{event_type}:{payload_str}"
            merkle_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()

            cursor.execute("""
                INSERT INTO security_events (
                    id, timestamp, event_type, severity, target_tool,
                    source_agent, raw_payload, sanitized_payload,
                    action_taken, prev_hash, merkle_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                evt_id, ts, event_type, severity, target_tool,
                source_agent, raw_payload, sanitized_payload,
                action_taken, prev_hash, merkle_hash
            ))
            conn.commit()

        return {
            "id": evt_id,
            "timestamp": ts,
            "event_type": event_type,
            "prev_hash": prev_hash,
            "merkle_hash": merkle_hash,
            "action_taken": action_taken
        }

    def verify_integrity(self) -> Tuple[bool, str, int]:
        """
        Walks the entire ledger sequentially and verifies both hash pointers and data integrity.
        Returns: (is_valid, message, count)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, event_type, raw_payload, prev_hash, merkle_hash 
                FROM security_events ORDER BY rowid ASC
            """)
            rows = cursor.fetchall()

        if not rows:
            return True, "Ledger is empty and valid.", 0

        expected_prev = "0" * 64
        for idx, (evt_id, ts, evt_type, raw_payload, prev_hash, stored_hash) in enumerate(rows):
            # 1. Verify pointer link
            if prev_hash != expected_prev:
                return False, f"Broken chain pointer at row {idx + 1} (Event {evt_id}). Expected {expected_prev}, got {prev_hash}", idx

            # 2. Recompute Merkle Hash
            payload_str = raw_payload or ""
            hash_input = f"{prev_hash}:{evt_id}:{ts}:{evt_type}:{payload_str}"
            computed_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()

            if computed_hash != stored_hash:
                return False, f"Tampered record at row {idx + 1} (Event {evt_id}). Computed hash does not match stored hash.", idx

            expected_prev = stored_hash

        return True, f"Successfully verified {len(rows)} cryptographically linked events.", len(rows)

    def generate_canary(self, label: str) -> str:
        """Creates a new unique canary token string and registers it in SQLite."""
        token_str = f"CANARY_{uuid.uuid4().hex[:16]}"
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO canary_tokens (token_id, token_string, label, created_at)
                VALUES (?, ?, ?, ?)
            """, (str(uuid.uuid4()), token_str, label, int(time.time() * 1000)))
            conn.commit()
        return token_str

    def check_for_canaries(self, text: str) -> List[Dict[str, Any]]:
        """Scans text for any registered canary token triggers."""
        if not text:
            return []

        triggered = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT token_id, token_string, label FROM canary_tokens WHERE status = 'ACTIVE'")
            tokens = cursor.fetchall()

            for t_id, t_str, label in tokens:
                if t_str in text:
                    now = int(time.time() * 1000)
                    cursor.execute("""
                        UPDATE canary_tokens 
                        SET trigger_count = trigger_count + 1, last_triggered_at = ?, status = 'TRIGGERED'
                        WHERE token_id = ?
                    """, (now, t_id))
                    triggered.append({"token_id": t_id, "token_string": t_str, "label": label})
            conn.commit()

        return triggered
