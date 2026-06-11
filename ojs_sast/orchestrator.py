"""Scan orchestrator.

Performs OJS detection, ruleset loading, sequential module execution,
de-duplication, severity filtering and report generation.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

from . import __version__
from .detectors.config_scanner import (ConfigScanner, extract_upload_dirs,
                                        parse_config)
from .detectors.cve_scanner import CVEScanner
from .detectors.upload_manifest_scanner import UploadManifestScanner
from .detectors.upload_scanner import UploadScanner
from .models import Finding, ScanResult, Severity, sort_findings
from .models.bundle import ScanBundle
from .models.report import ScanReport
from .reporters import (generate_html_report, generate_json_report,
                        generate_sarif_report)
from .ruleset.loader import Ruleset, load_ruleset

logger = logging.getLogger("ojs_sast.orchestrator")

ALL_MODULES = ["source_code", "config", "upload_directory"]
_DEFAULT_NGINX_PATHS = [
    "/etc/nginx/sites-enabled",
    "/etc/nginx/conf.d",
    "/etc/nginx/nginx.conf",
]
_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


@dataclass
class OJSInfo:
    is_ojs: bool
    config_path: Optional[Path]
    version: Optional[str]
    markers: List[str] = field(default_factory=list)


def detect_ojs(ojs_path: Path) -> OJSInfo:
    """Verify the path looks like an OJS install and detect its version."""
    ojs_path = Path(ojs_path)
    config_path = ojs_path / "config.inc.php"
    markers: List[str] = []
    if config_path.is_file():
        markers.append("config.inc.php")
    core_markers = [
        ojs_path / "lib" / "pkp",
        ojs_path / "classes" / "core" / "Application.php",
        ojs_path / "classes" / "core" / "PKPApplication.php",
        ojs_path / "lib" / "pkp" / "classes" / "core" / "PKPApplication.php",
    ]
    for m in core_markers:
        if m.exists():
            markers.append(str(m.relative_to(ojs_path)))
    is_ojs = config_path.is_file() and len(markers) >= 2
    version = _detect_version(ojs_path)
    return OJSInfo(is_ojs=is_ojs,
                   config_path=config_path if config_path.is_file() else None,
                   version=version, markers=markers)


def _detect_version(ojs_path: Path) -> Optional[str]:
    candidates = [
        ojs_path / "dbscripts" / "xml" / "version.xml",
        ojs_path / "lib" / "pkp" / "dbscripts" / "xml" / "version.xml",
    ]
    for c in candidates:
        if c.is_file():
            try:
                text = c.read_text(encoding="utf-8", errors="replace")
            except OSError:  # pragma: no cover
                continue
            m = re.search(r"<release>\s*([^<\s]+)\s*</release>", text)
            if m:
                return m.group(1)
    return None


class Orchestrator:
    def __init__(
        self,
        ojs_path: Path,
        *,
        ruleset_dir: Optional[Path] = None,
        output_dir: Path = Path("./ojs_sast_report"),
        formats: Sequence[str] = ("json", "html"),
        min_severity: Severity = Severity.INFO,
        categories: Optional[Sequence[str]] = None,
        upload_dir_override: Optional[Path] = None,
        skip_source: bool = False,
        skip_config: bool = False,
        skip_upload: bool = False,
        nginx_config: Optional[Path] = None,
        ojs_version: Optional[str] = None,
        verbose: bool = False,
        progress_cb: Optional[Callable[[str], None]] = None,
        ruleset: Optional[Ruleset] = None,
    ):
        self.ojs_path = Path(ojs_path)
        self.ruleset_dir = Path(ruleset_dir) if ruleset_dir else None
        self.output_dir = Path(output_dir)
        self.formats = [f.strip().lower() for f in formats if f.strip()]
        self.min_severity = min_severity
        self.categories = set(categories) if categories else None
        self.upload_dir_override = Path(upload_dir_override) if upload_dir_override else None
        self.skip_source = skip_source
        self.skip_config = skip_config
        self.skip_upload = skip_upload
        self.nginx_config = Path(nginx_config) if nginx_config else None
        self.forced_version = ojs_version
        self.verbose = verbose
        self.progress_cb = progress_cb
        self.ruleset = ruleset or load_ruleset(self.ruleset_dir)
        self.files_scanned: Dict[str, int] = {}

    def _progress(self, msg: str) -> None:
        if self.progress_cb:
            self.progress_cb(msg)

    def _modules_to_run(self) -> List[str]:
        mods = list(ALL_MODULES)
        if self.skip_source:
            mods.remove("source_code")
        if self.skip_config:
            mods.remove("config")
        if self.skip_upload and "upload_directory" in mods:
            mods.remove("upload_directory")
        if self.categories:
            mods = [m for m in mods if m in self.categories]
        return mods

    # ------------------------------------------------------------------ #
    def run(self) -> ScanResult:
        """Run a local scan of ``self.ojs_path`` (the original behavior)."""
        return self.run_local()

    def run_local(self, ojs_path: Optional[Path] = None) -> ScanResult:
        """Scan an OJS install directly on the local filesystem.

        ``ojs_path`` defaults to ``self.ojs_path``; this is the unchanged
        single-host behavior, now expressed as one of two entry points.
        """
        start = time.time()
        target = Path(ojs_path) if ojs_path is not None else self.ojs_path
        info = detect_ojs(target)
        version = self.forced_version or info.version
        if info.is_ojs:
            self._progress(f"Detected OJS at {target} (version {version or 'unknown'})")
        else:
            logger.warning(
                "Path does not look like a complete OJS install (markers: %s). Continuing anyway.",
                ", ".join(info.markers) or "none",
            )
            self._progress("Warning: target does not look like a full OJS install; continuing.")

        modules = self._modules_to_run()
        logger.info("Modules to run: %s", ", ".join(modules))
        self._progress(f"Loaded {len(self.ruleset)} rules "
                       f"({self.ruleset.counts_by_module()})")

        findings: List[Finding] = []
        config_sections = self._load_config_sections(info.config_path)

        if "source_code" in modules:
            self._progress("Scanning source code…")
            scanner = CVEScanner(self.ruleset, ojs_version=version,
                                 verbose=self.verbose, progress_cb=self.progress_cb)
            findings.extend(scanner.scan(target))
            self.files_scanned["source_code"] = scanner.files_scanned

        if "config" in modules:
            self._progress("Scanning configuration…")
            cfg_scanner = ConfigScanner(self.ruleset, ojs_path=target,
                                        ojs_version=version, verbose=self.verbose)
            findings.extend(cfg_scanner.scan(info.config_path, self._resolve_nginx_paths()))

        if "upload_directory" in modules:
            upload_dirs = self._resolve_upload_dirs(config_sections)
            if upload_dirs:
                self._progress(f"Scanning {len(upload_dirs)} upload dir(s)…")
                up_scanner = UploadScanner(self.ruleset, ojs_path=self.ojs_path,
                                           verbose=self.verbose, progress_cb=self.progress_cb)
                findings.extend(up_scanner.scan(upload_dirs))
                self.files_scanned["upload_directory"] = up_scanner.files_scanned
            else:
                logger.warning("No upload directories resolved; skipping upload scan.")
                self._progress("No upload directories found; skipping upload scan.")

        return self._finalize(
            findings, modules, version, start,
            ojs_detected=info.is_ojs,
            detection_markers=info.markers,
            ojs_path_label=str(target),
            extra_metadata={"scan_mode": "local"},
        )

    def run_bundle(self, bundle: ScanBundle) -> ScanResult:
        """Scan an agent-supplied bundle (extracted source + config payload +
        upload manifest) instead of a live filesystem.

        The source archive must already be safely extracted into
        ``bundle.source_root`` by the caller. OJS version / detection facts are
        taken from the bundle (computed agent-side on the full install).
        """
        start = time.time()
        version = self.forced_version or bundle.ojs_version
        if bundle.ojs_detected:
            self._progress(f"Scanning bundle (OJS version {version or 'unknown'})")
        else:
            self._progress("Scanning bundle (target not confirmed as OJS; continuing).")

        modules = self._modules_to_run()
        logger.info("Modules to run (bundle): %s", ", ".join(modules))
        self._progress(f"Loaded {len(self.ruleset)} rules "
                       f"({self.ruleset.counts_by_module()})")

        findings: List[Finding] = []

        if "source_code" in modules and bundle.source_root is not None:
            self._progress("Scanning source snapshot…")
            scanner = CVEScanner(self.ruleset, ojs_version=version,
                                 verbose=self.verbose, progress_cb=self.progress_cb)
            findings.extend(scanner.scan(bundle.source_root))
            self.files_scanned["source_code"] = scanner.files_scanned

        if "config" in modules and bundle.config_files:
            self._progress("Scanning configuration payload…")
            cfg_scanner = ConfigScanner(self.ruleset, ojs_path=None,
                                        ojs_version=version, verbose=self.verbose)
            findings.extend(cfg_scanner.scan_payload(bundle.config_files))
            self.files_scanned["config"] = len(bundle.config_files)

        if "upload_directory" in modules and bundle.upload_manifest is not None:
            self._progress(f"Scanning {len(bundle.upload_manifest)} manifest entry(ies)…")
            up_scanner = UploadManifestScanner(self.ruleset, verbose=self.verbose,
                                               progress_cb=self.progress_cb)
            findings.extend(up_scanner.scan(bundle.upload_manifest))
            self.files_scanned["upload_directory"] = up_scanner.files_scanned

        entries = bundle.upload_manifest or []
        upload_total = sum(
            int(e.get("size_bytes") or e.get("size") or 0)
            for e in entries if isinstance(e, dict)
        )

        return self._finalize(
            findings, modules, version, start,
            ojs_detected=bundle.ojs_detected,
            detection_markers=bundle.detection_markers,
            ojs_path_label=bundle.source_label or "remote-bundle",
            extra_metadata={
                "scan_mode": "remote",
                "agent_id": bundle.agent_id,
                "agent_version": bundle.agent_version,
                "agent_hostname": bundle.agent_hostname,
                "bundle_id": bundle.bundle_id,
                "config_payload_mode": "raw_text",
                "source_archive_sha256": bundle.source_archive_sha256,
                "source_archive_bytes": bundle.source_archive_bytes,
                "upload_manifest_entries": len(entries),
                "upload_total_size_bytes": upload_total,
                "bundle_created_at": bundle.created_at,
            },
        )

    # ------------------------------------------------------------------ #
    def _finalize(
        self,
        findings: List[Finding],
        modules: List[str],
        version: Optional[str],
        start: float,
        *,
        ojs_detected: bool,
        detection_markers: List[str],
        ojs_path_label: str,
        extra_metadata: Optional[Dict[str, object]] = None,
    ) -> ScanResult:
        """Deduplicate, severity-filter, assemble metadata and build the result.

        Shared by ``run_local`` and ``run_bundle`` so both produce the identical
        13 base metadata keys. ``extra_metadata`` is applied additively and must
        never overwrite an existing key.
        """
        deduped = self._deduplicate(findings)
        filtered = [f for f in deduped if f.severity.rank >= self.min_severity.rank]

        metadata = {
            "tool": "ojs-sast",
            "version": __version__,
            "ojs_path": ojs_path_label,
            "ojs_version": version or "unknown",
            "ojs_detected": ojs_detected,
            "detection_markers": detection_markers,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "modules_run": modules,
            "rules_loaded": len(self.ruleset),
            "files_scanned": self.files_scanned,
            "min_severity": self.min_severity.value,
            "duration_seconds": round(time.time() - start, 3),
            "findings_before_dedup": len(findings),
            "findings_after_dedup": len(deduped),
        }
        if extra_metadata:
            for key, value in extra_metadata.items():
                if key not in metadata:  # additive only; never clobber a base key
                    metadata[key] = value

        result = ScanResult(metadata=metadata, findings=filtered)
        logger.info("Scan finished in %.2fs: %d findings (%d before dedup)",
                    metadata["duration_seconds"], len(filtered), len(findings))
        return result

    # ------------------------------------------------------------------ #
    def _load_config_sections(self, config_path: Optional[Path]):
        if config_path and Path(config_path).is_file():
            try:
                return parse_config(Path(config_path).read_text(encoding="utf-8", errors="replace"))
            except OSError:  # pragma: no cover
                return {}
        return {}

    def _resolve_upload_dirs(self, sections) -> List[Path]:
        if self.upload_dir_override:
            return [self.upload_dir_override]
        dirs: List[Path] = []
        files_dir, public_dir = extract_upload_dirs(sections) if sections else (None, None)
        for raw in (files_dir, public_dir):
            if not raw:
                continue
            p = Path(raw)
            if not p.is_absolute():
                p = self.ojs_path / raw
            if p.is_dir():
                dirs.append(p)
            else:
                logger.debug("Configured upload dir does not exist: %s", p)
        # Common fallback: a 'public' directory under the install.
        if not dirs:
            fallback = self.ojs_path / "public"
            if fallback.is_dir():
                dirs.append(fallback)
        return dirs

    def _resolve_nginx_paths(self) -> List[Path]:
        if self.nginx_config:
            return [self.nginx_config]
        return [Path(p) for p in _DEFAULT_NGINX_PATHS if Path(p).exists()]

    @staticmethod
    def _deduplicate(findings: List[Finding]) -> List[Finding]:
        """Merge findings with the same (rule_id, file, line, discriminator).

        Keeps the highest severity; ties broken by confidence. CVE references and
        a code snippet are merged from the dropped duplicate when richer.
        """
        best: Dict[tuple, Finding] = {}
        for f in findings:
            key = f.dedup_key
            cur = best.get(key)
            if cur is None:
                best[key] = f
                continue
            f_score = (f.severity.rank, _CONFIDENCE_RANK.get(f.confidence, 0))
            cur_score = (cur.severity.rank, _CONFIDENCE_RANK.get(cur.confidence, 0))
            keep, drop = (f, cur) if f_score > cur_score else (cur, f)
            for cve in drop.cve_references:
                if cve not in keep.cve_references:
                    keep.cve_references.append(cve)
            if not keep.code_snippet and drop.code_snippet:
                keep.code_snippet = drop.code_snippet
            best[key] = keep
        return sort_findings(list(best.values()))

    # ------------------------------------------------------------------ #
    def generate_reports(self, result: ScanResult) -> Dict[str, Path]:
        written: Dict[str, Path] = {}
        formats = set(self.formats)
        # JSON is always produced (per spec).
        formats.add("json")
        
        ojs_version = result.metadata.get("ojs_version", "unknown")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        subfolder_name = f"{timestamp}_{ojs_version}"
        target_dir = self.output_dir / subfolder_name
        
        # The reporters write directly into target_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        report = ScanReport.from_scan_result(result)
        out_dir = str(target_dir)
        if "json" in formats:
            written["json"] = Path(generate_json_report(report, out_dir))
        if "html" in formats:
            written["html"] = Path(generate_html_report(report, out_dir))
        if "sarif" in formats:
            written["sarif"] = Path(generate_sarif_report(report, out_dir))
        return written
