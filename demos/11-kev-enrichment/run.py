"""Demo: cross-reference firmware/platform component CVEs against CISA KEV.

Runs fully OFFLINE against the committed trimmed KEV fixture, so it works on a
disconnected / air-gapped box. Standard library only.
"""

from __future__ import annotations

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
sys.path.insert(0, _ROOT)

# Point the feed cache at the committed offline fixture before importing feeds.
_FIXTURE = os.path.join(_ROOT, "tests", "fixtures", "feeds-cache")


def run(offline: bool = True) -> dict:
    os.environ["COGNIS_FEEDS_CACHE"] = _FIXTURE
    from bootwarden import feeds

    # A representative component CVE list for a UEFI/BMC platform. Two of these
    # are real KEV entries; the last is deliberately not exploited-in-the-wild.
    component_cves = [
        "CVE-2025-47827",  # IGEL OS Secure Boot bypass (real KEV entry)
        "CVE-2022-0492",   # Linux kernel cgroups priv-esc (real KEV entry)
        "CVE-2099-00000",  # synthetic: not in KEV
    ]
    report = feeds.enrich_cves(component_cves, offline=offline)
    return report


def main() -> int:
    report = run(offline=True)
    print("CISA KEV enrichment (offline fixture)")
    print("  catalog size : {}".format(report["kev_catalog_size"]))
    print("  checked      : {}".format(report["total"]))
    print("  exploited    : {}".format(report["known_exploited"]))
    print("  ransomware   : {}".format(report["ransomware_linked"]))
    print()
    for it in report["items"]:
        if it["known_exploited"]:
            print("  [KEV] {}  {} {}  due {}".format(
                it["cve"], it["vendor"], it["product"], it["due_date"]))
        else:
            print("  [ -- ] {}  not in KEV".format(it["cve"]))
    print()
    print("PATCH NOW: {}".format(", ".join(report["patch_now"]) or "(none)"))
    print()
    print(json.dumps(report, indent=2)[:1200])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
