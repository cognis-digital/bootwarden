"""Passive (offline, default) analysis helpers for BOOTWARDEN.

Passive mode is the safe default: it analyses inputs you *already have* with no
network and no contact with any device. The firmware-dump path lives in
:mod:`bootwarden.core`; this module adds offline analysis of the *other* artifacts
a defender already holds:

  * SBOMs (CycloneDX or SPDX-tag-value) — extract component CVE ids so they can
    be cross-referenced against the bundled/cached KEV feed.
  * A plain CVE list (one id per line, ``#`` comments allowed).
  * Batch firmware scanning of a directory of dumps.

Everything here is pure-stdlib and offline.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List

from .core import audit_image, AuditResult

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Common firmware-dump extensions; used for directory batch scans.
FIRMWARE_EXTS = (".bin", ".rom", ".fd", ".cap", ".img", ".fv")


def extract_cves_from_text(text: str) -> List[str]:
    """Return unique, upper-cased CVE ids found in arbitrary text, in order."""
    out: List[str] = []
    seen = set()
    for m in _CVE_RE.findall(text or ""):
        u = m.upper()
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def parse_cve_list(text: str) -> List[str]:
    """Parse a newline-delimited CVE list (``#`` comments + blanks ignored)."""
    out: List[str] = []
    seen = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        for m in _CVE_RE.findall(line):
            u = m.upper()
            if u not in seen:
                seen.add(u)
                out.append(u)
    return out


def extract_cves_from_sbom(data) -> List[str]:
    """Extract CVE ids referenced by an SBOM (CycloneDX JSON or SPDX text).

    Accepts a JSON string, a parsed dict (CycloneDX), or SPDX tag-value text.
    Returns unique upper-cased CVE ids. Pure offline parsing.
    """
    # CycloneDX (dict or JSON string)
    obj = None
    if isinstance(data, dict):
        obj = data
    elif isinstance(data, (bytes, bytearray)):
        data = data.decode("utf-8", "replace")
    if obj is None and isinstance(data, str):
        stripped = data.lstrip()
        if stripped.startswith("{"):
            try:
                obj = json.loads(data)
            except json.JSONDecodeError:
                obj = None
    if isinstance(obj, dict):
        cves: List[str] = []
        seen = set()
        # CycloneDX vulnerabilities[].id and .references
        for vuln in obj.get("vulnerabilities", []) or []:
            for cand in [vuln.get("id", "")] + [
                r.get("id", "") for r in (vuln.get("references") or [])
            ]:
                for u in extract_cves_from_text(str(cand)):
                    if u not in seen:
                        seen.add(u)
                        cves.append(u)
        # Also sweep component property values for embedded CVE refs.
        for comp in obj.get("components", []) or []:
            for u in extract_cves_from_text(json.dumps(comp)):
                if u not in seen:
                    seen.add(u)
                    cves.append(u)
        return cves
    # Fall back to a plain text sweep (covers SPDX tag-value + free text).
    return extract_cves_from_text(data if isinstance(data, str) else str(data))


def scan_directory(path: str, recursive: bool = True) -> Dict[str, AuditResult]:
    """Audit every firmware-looking file under `path`. Returns {path: result}."""
    results: Dict[str, AuditResult] = {}
    if os.path.isfile(path):
        results[path] = audit_image(path)
        return results
    walker = os.walk(path) if recursive else [(path, [], os.listdir(path))]
    for root, _dirs, files in walker:
        for name in sorted(files):
            if name.lower().endswith(FIRMWARE_EXTS):
                fp = os.path.join(root, name)
                try:
                    results[fp] = audit_image(fp)
                except OSError:
                    continue
    return results


def enrich_with_local_vulndb(cves: List[str]) -> Dict[str, dict]:
    """Annotate CVEs with offline metadata from the bundled vuln DB, if present.

    Returns ``{cve: {"severity": ..., "summary": ..., "ecosystem": ...}}`` for
    any CVE found in the bundled 262k-record corpus. Fully offline; if the
    bundled gz is missing this simply returns an empty mapping.
    """
    out: Dict[str, dict] = {}
    try:
        from .vulndb_local import VulnDB
    except Exception:
        return out
    try:
        db = VulnDB()
        if not db.path.exists():
            return out
        for cve in cves:
            recs = db.by_cve(cve)
            if recs:
                r = recs[0]
                out[cve.upper()] = {
                    "severity": r.get("severity", ""),
                    "summary": r.get("summary", ""),
                    "ecosystem": r.get("ecosystem", ""),
                }
    except Exception:
        return out
    return out


def summarize_batch(results: Dict[str, AuditResult]) -> dict:
    """Roll up a batch scan into pass/fail counts and a per-file verdict map."""
    verdicts = {p: r.verdict for p, r in results.items()}
    passed = sum(1 for v in verdicts.values() if v == "PASS")
    failed = len(verdicts) - passed
    return {
        "tool": "bootwarden",
        "mode": "passive-batch",
        "scanned": len(verdicts),
        "passed": passed,
        "failed": failed,
        "verdicts": verdicts,
    }
