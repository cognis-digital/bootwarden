"""Data-feed enrichment for BOOTWARDEN.

BOOTWARDEN audits a firmware image for Secure Boot / module-signing problems.
This module adds a *real* threat-intelligence layer on top of that audit:
the **CISA Known Exploited Vulnerabilities (KEV)** catalog. KEV is the
authoritative US-government list of CVEs that are being actively exploited in
the wild and carry a federal remediation deadline (CISA BOD 22-01 / 26-04).

The enrichment is concrete, not cosmetic:

  * It builds an index of the KEV catalog (CVE -> record).
  * Given a set of CVE identifiers attached to firmware / platform components
    (e.g. a BMC/UEFI BIOS SBOM, a boot-chain bill of CVEs, or CVEs surfaced by
    a firmware scan), it flags exactly which are **known-exploited** and
    therefore must be patched first, attaches the vendor, the federal
    ``dueDate``, and a ``knownRansomwareCampaignUse`` marker, and sorts the
    result so the must-patch-now items float to the top.
  * It can also enrich an :class:`bootwarden.core.AuditResult` in place: any CVE
    referenced in a finding message is checked against KEV and the finding is
    re-leveled to ``error`` with a ``[KEV: known exploited]`` annotation.

Edge / air-gap design
---------------------
All ingestion goes through the bundled, stdlib-only :mod:`bootwarden.datafeeds`
module, which fetches over HTTPS, caches to disk, and re-serves the cache when
``offline=True`` so the tool keeps working on a disconnected enclave. Point
``COGNIS_FEEDS_CACHE`` at a directory holding a snapshot and pass
``offline=True`` to run with zero network access.

Defensive / authorized-use intelligence only.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional

from . import datafeeds

# This tool only consumes the feeds relevant to firmware/vuln triage.
# Do NOT widen this set without a real enrichment behind it.
RELEVANT_FEEDS = ("cisa-kev",)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _check_relevant(feed_id: str) -> None:
    if feed_id not in RELEVANT_FEEDS:
        raise KeyError(
            "bootwarden only consumes {}; refusing feed {!r}".format(
                ", ".join(RELEVANT_FEEDS), feed_id
            )
        )


# --------------------------------------------------------------------------- #
# KEV ingestion + index
# --------------------------------------------------------------------------- #
def load_kev(*, offline: bool = False, max_age_hours: float = 24.0) -> dict:
    """Return the raw CISA KEV catalog dict (cached/fetched per offline flag)."""
    _check_relevant("cisa-kev")
    return datafeeds.get("cisa-kev", offline=offline, max_age_hours=max_age_hours)


def kev_index(catalog: Optional[dict] = None, *, offline: bool = False) -> Dict[str, dict]:
    """Map ``CVE-id (upper) -> KEV record`` for fast membership tests."""
    cat = catalog if catalog is not None else load_kev(offline=offline)
    out: Dict[str, dict] = {}
    for rec in cat.get("vulnerabilities", []):
        cve = (rec.get("cveID") or "").upper()
        if cve:
            out[cve] = rec
    return out


def _ransomware(rec: dict) -> bool:
    return str(rec.get("knownRansomwareCampaignUse", "")).strip().lower() == "known"


# --------------------------------------------------------------------------- #
# Enrichment 1: flag a component CVE list against KEV
# --------------------------------------------------------------------------- #
def enrich_cves(
    cves: Iterable[str],
    *,
    offline: bool = False,
    catalog: Optional[dict] = None,
) -> dict:
    """Cross-reference component CVEs against the CISA KEV catalog.

    ``cves`` is any iterable of CVE ids (e.g. from a firmware/BMC SBOM or a
    boot-chain advisory). Returns a dict with a per-CVE verdict and a
    prioritised, must-patch-now list.

    The result is the real payload a defender acts on: which firmware CVEs are
    being exploited *right now* and have a federal remediation deadline.
    """
    idx = kev_index(catalog, offline=offline)
    seen: List[str] = []
    norm: List[str] = []
    for c in cves:
        u = str(c).strip().upper()
        if u and u not in seen:
            seen.append(u)
            norm.append(u)

    items: List[dict] = []
    for cve in norm:
        rec = idx.get(cve)
        if rec is None:
            items.append({"cve": cve, "known_exploited": False})
            continue
        items.append(
            {
                "cve": cve,
                "known_exploited": True,
                "vendor": rec.get("vendorProject", ""),
                "product": rec.get("product", ""),
                "name": rec.get("vulnerabilityName", ""),
                "date_added": rec.get("dateAdded", ""),
                "due_date": rec.get("dueDate", ""),
                "ransomware": _ransomware(rec),
                "required_action": rec.get("requiredAction", ""),
            }
        )

    # Prioritise: ransomware-linked first, then by federal due date.
    exploited = [i for i in items if i["known_exploited"]]
    exploited.sort(key=lambda i: (not i["ransomware"], i.get("due_date") or "9999"))

    return {
        "total": len(norm),
        "known_exploited": len(exploited),
        "ransomware_linked": sum(1 for i in exploited if i["ransomware"]),
        "kev_catalog_size": len(idx),
        "patch_now": [i["cve"] for i in exploited],
        "items": items,
        "prioritised": exploited,
    }


# --------------------------------------------------------------------------- #
# Enrichment 2: enrich an AuditResult's findings in place
# --------------------------------------------------------------------------- #
def enrich_audit_result(result, *, offline: bool = False, catalog: Optional[dict] = None) -> dict:
    """Scan an :class:`AuditResult`'s findings for CVE ids and flag KEV hits.

    Any finding whose message references a CVE that is in the KEV catalog gets
    re-leveled to ``error`` and annotated; returns a summary of what fired.
    Findings with no CVE reference are untouched, so a clean firmware audit is
    unaffected.
    """
    idx = kev_index(catalog, offline=offline)
    flagged: List[str] = []
    for f in result.findings:
        for cve in {m.upper() for m in _CVE_RE.findall(f.message or "")}:
            if cve in idx:
                flagged.append(cve)
                if "[KEV:" not in f.message:
                    f.level = "error"
                    f.message = "{}  [KEV: {} known-exploited, due {}]".format(
                        f.message, cve, idx[cve].get("dueDate", "n/a")
                    )
    return {
        "kev_catalog_size": len(idx),
        "flagged": sorted(set(flagged)),
        "flagged_count": len(set(flagged)),
    }
