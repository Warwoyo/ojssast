"""Configuration collector (agent side).

Reads ``config.inc.php`` and (best-effort) the web-server configs on the local
node, returning a ``{logical_name: raw_text}`` payload for the service's
``ConfigScanner.scan_payload``. Raw contents are never logged (they may contain
credentials).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger("ojs_sast.agent.config")

_DEFAULT_NGINX_PATHS = [
    "/etc/nginx/sites-enabled",
    "/etc/nginx/conf.d",
    "/etc/nginx/nginx.conf",
]
_DEFAULT_APACHE_PATHS = [
    "/etc/apache2/sites-enabled",
    "/etc/httpd/conf.d",
]


def _read_config_files(candidate) -> List[Tuple[str, str]]:
    """Return ``(path, text)`` for each readable file under ``candidate``."""
    p = Path(candidate)
    files: List[Path] = []
    if p.is_dir():
        files = [f for f in sorted(p.rglob("*")) if f.is_file()]
    elif p.is_file():
        files = [p]
    out: List[Tuple[str, str]] = []
    for f in files:
        try:
            out.append((str(f), f.read_text(encoding="utf-8", errors="replace")))
        except OSError:  # pragma: no cover
            continue
    return out


def collect_configs(
    ojs_root,
    *,
    nginx_paths: Optional[Sequence[str]] = None,
    apache_paths: Optional[Sequence[str]] = None,
    include_system_configs: bool = True,
) -> Dict[str, str]:
    """Collect config payloads keyed by logical name.

    ``config.inc.php`` is keyed verbatim; web-server files are keyed
    ``"nginx:<path>"`` / ``"apache:<path>"`` so the service routes them through
    the nginx checks while preserving a readable label.
    """
    ojs_root = Path(ojs_root)
    files: Dict[str, str] = {}

    config_path = ojs_root / "config.inc.php"
    if config_path.is_file():
        try:
            files["config.inc.php"] = config_path.read_text(encoding="utf-8", errors="replace")
        except OSError:  # pragma: no cover
            logger.warning("config.inc.php present but unreadable")

    nginx_candidates: List[str] = list(nginx_paths or [])
    apache_candidates: List[str] = list(apache_paths or [])
    if include_system_configs:
        nginx_candidates += _DEFAULT_NGINX_PATHS
        apache_candidates += _DEFAULT_APACHE_PATHS

    for cand in nginx_candidates:
        for path_str, text in _read_config_files(cand):
            files[f"nginx:{path_str}"] = text
    for cand in apache_candidates:
        for path_str, text in _read_config_files(cand):
            files[f"apache:{path_str}"] = text

    return files
