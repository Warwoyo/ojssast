"""Authentication, IP allowlisting and audit logging (pure stdlib).

Kept free of FastAPI so it can be unit-tested without the ``service`` extra.
Never logs raw API keys or configuration contents.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

logger = logging.getLogger("ojs_sast.service.auth")


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def api_key_id(raw: str) -> str:
    """A short, non-reversible identifier for a key (for audit/storage)."""
    return hash_api_key(raw)[:12]


def verify_api_key(presented: str, api_keys: Dict[str, Optional[str]]) -> Optional[str]:
    """Return the agent id (or a hash prefix) for a valid key, else ``None``.

    Uses a constant-time comparison against every configured hash.
    """
    if not presented:
        return None
    presented_hash = hash_api_key(presented)
    match: Optional[str] = None
    for stored_hash, agent_id in api_keys.items():
        if hmac.compare_digest(presented_hash, stored_hash):
            match = agent_id or stored_hash[:12]
    return match


def ip_allowed(client_ip: str, allowlist: Sequence[str]) -> bool:
    if not allowlist:
        return True
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    for entry in allowlist:
        try:
            if ip in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            if client_ip == entry:
                return True
    return False


def write_audit(audit_log_path, event: Dict[str, Any]) -> None:
    """Append a single JSON audit record. Never include secrets or config text."""
    if not audit_log_path:
        return
    record = {"ts": datetime.now(timezone.utc).isoformat(), **event}
    try:
        path = Path(audit_log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError as exc:  # pragma: no cover
        logger.warning("could not write audit log: %s", exc)
