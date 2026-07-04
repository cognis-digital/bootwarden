# Demo 11 — CISA KEV firmware-CVE enrichment (offline)

A real-world firmware / platform component list almost always ships with a set
of CVE references (from the vendor advisory, a BMC/UEFI SBOM, or a boot-chain
bill of materials). The question a defender actually has is: **which of these
are being exploited right now and have a federal patch deadline?**

This demo answers that with the bundled CISA **Known Exploited Vulnerabilities
(KEV)** feed — entirely offline, against a trimmed real-data fixture.

```
python demos/11-kev-enrichment/run.py
```

It cross-references a sample component CVE list against KEV and prints a
prioritised "patch now" list (ransomware-linked first, then by federal due
date). Two of the sample CVEs are genuine KEV entries — e.g.
`CVE-2025-47827`, an IGEL OS **Secure Boot bypass** — and are flagged; an
invented `CVE-2099-00000` is correctly reported as *not* in KEV.

The same data also drives `bootwarden feeds get --cve <id> --offline`.

Edge / air-gap: the run sets `COGNIS_FEEDS_CACHE` to the committed fixture and
uses `offline=True`, so it never touches the network. In production you would
`bootwarden feeds update` while connected, `snapshot-export` the cache, sneakernet
it into the enclave, `snapshot-import`, then run with `--offline`.
