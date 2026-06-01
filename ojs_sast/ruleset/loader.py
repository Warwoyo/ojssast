"""YAML ruleset loader.

Loads all ``*_rules.yaml`` files from a ruleset directory, validates a minimal
schema, and returns :class:`~ojs_sast.models.Rule` objects keyed by id and
grouped by module.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from ..models import Rule, Severity

logger = logging.getLogger("ojs_sast.ruleset")

# Default ruleset directory shipped with the package.
DEFAULT_RULESET_DIR = Path(__file__).resolve().parent

REQUIRED_FIELDS = ("id", "name", "module", "severity")
VALID_MODULES = {"source_code", "config", "upload_directory"}
VALID_PATTERN_TYPES = {"regex", "smarty", "ast", "taint", "builtin", "cve"}


class RulesetError(Exception):
    """Raised when a ruleset file is structurally invalid."""


@dataclass
class Ruleset:
    """A loaded collection of rules with convenient lookup helpers."""

    rules: List[Rule] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._by_id: Dict[str, Rule] = {r.id: r for r in self.rules}

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self):
        return iter(self.rules)

    def get(self, rule_id: str) -> Optional[Rule]:
        return self._by_id.get(rule_id)

    def by_module(self, module: str) -> List[Rule]:
        return [r for r in self.rules if r.module == module]

    def counts_by_module(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for r in self.rules:
            counts[r.module] = counts.get(r.module, 0) + 1
        return counts


def _parse_rule(raw: dict, source_file: Path) -> Rule:
    missing = [f for f in REQUIRED_FIELDS if f not in raw or raw[f] in (None, "")]
    if missing:
        raise RulesetError(
            f"Rule in {source_file.name} missing required field(s): {', '.join(missing)} "
            f"(rule id={raw.get('id', '?')})"
        )

    module = raw["module"]
    if module not in VALID_MODULES:
        raise RulesetError(
            f"Rule {raw['id']} in {source_file.name} has invalid module {module!r}; "
            f"expected one of {sorted(VALID_MODULES)}"
        )

    pattern_type = raw.get("pattern_type", "regex")
    if pattern_type not in VALID_PATTERN_TYPES:
        raise RulesetError(
            f"Rule {raw['id']} has invalid pattern_type {pattern_type!r}; "
            f"expected one of {sorted(VALID_PATTERN_TYPES)}"
        )

    try:
        severity = Severity.from_str(str(raw["severity"]))
    except ValueError as exc:
        raise RulesetError(f"Rule {raw['id']}: {exc}") from exc

    cvss = raw.get("cvss_score")
    if cvss is not None:
        try:
            cvss = float(cvss)
        except (TypeError, ValueError):
            raise RulesetError(f"Rule {raw['id']}: cvss_score must be numeric")

    # Collect any keys that are not part of the known schema into params.
    known = {
        "id", "name", "module", "severity", "cwe", "owasp", "pattern_type",
        "pattern", "description", "remediation", "cvss_score", "cve_references",
        "file_extensions", "false_positive_exceptions", "params",
    }
    params = dict(raw.get("params", {}) or {})
    for key, value in raw.items():
        if key not in known:
            params[key] = value

    return Rule(
        id=str(raw["id"]),
        name=str(raw["name"]),
        module=module,
        severity=severity,
        cwe=raw.get("cwe"),
        owasp=raw.get("owasp"),
        pattern_type=pattern_type,
        pattern=raw.get("pattern"),
        description=str(raw.get("description", "")),
        remediation=str(raw.get("remediation", "")),
        cvss_score=cvss,
        cve_references=list(raw.get("cve_references", []) or []),
        file_extensions=[e.lower() for e in (raw.get("file_extensions", []) or [])],
        false_positive_exceptions=list(raw.get("false_positive_exceptions", []) or []),
        params=params,
    )


def load_ruleset_file(path: Path) -> List[Rule]:
    """Load a single YAML ruleset file into a list of rules."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise RulesetError(f"Failed to parse YAML in {path}: {exc}") from exc

    if not isinstance(data, dict) or "rules" not in data:
        raise RulesetError(f"{path.name}: top-level 'rules' key is required")

    raw_rules = data.get("rules") or []
    if not isinstance(raw_rules, list):
        raise RulesetError(f"{path.name}: 'rules' must be a list")

    rules = [_parse_rule(r, path) for r in raw_rules]
    return rules


def load_ruleset(ruleset_dir: Optional[Path] = None) -> Ruleset:
    """Load and merge all ``*_rules.yaml`` files in ``ruleset_dir``.

    Duplicate rule ids raise :class:`RulesetError`.
    """
    directory = Path(ruleset_dir) if ruleset_dir else DEFAULT_RULESET_DIR
    if not directory.is_dir():
        raise RulesetError(f"Ruleset directory not found: {directory}")

    rule_files = sorted(directory.glob("*_rules.yaml"))
    if not rule_files:
        raise RulesetError(f"No '*_rules.yaml' files found in {directory}")

    all_rules: List[Rule] = []
    seen_ids: Dict[str, str] = {}
    for rf in rule_files:
        rules = load_ruleset_file(rf)
        for rule in rules:
            if rule.id in seen_ids:
                raise RulesetError(
                    f"Duplicate rule id {rule.id!r} found in {rf.name} "
                    f"(already defined in {seen_ids[rule.id]})"
                )
            seen_ids[rule.id] = rf.name
            all_rules.append(rule)
        logger.debug("Loaded %d rules from %s", len(rules), rf.name)

    ruleset = Ruleset(all_rules)
    logger.info(
        "Loaded %d rules from %d file(s): %s",
        len(ruleset),
        len(rule_files),
        ", ".join(f"{m}={c}" for m, c in ruleset.counts_by_module().items()),
    )
    return ruleset
