# Demo 09 - wiring BOOTWARDEN into CI (FAIL gate + SARIF upload)

**Where this comes from.** A firmware build pipeline produces an image on every
commit. You want the build to **break** when the image regresses, and you want
the findings to show up in GitHub's Security tab via SARIF.

**What's in the image.**
* One valid firmware volume; all four Secure Boot keys present.
* A single **unsigned** PE module - i.e. a regression that must fail the gate.

## Run it

```sh
# Fail the job on any error-level finding (exit 1)
python -m bootwarden scan demos/09-ci-gate/firmware.bin || echo "audit FAILED"

# Emit SARIF for code-scanning upload
python -m bootwarden scan demos/09-ci-gate/firmware.bin --format sarif -o bootwarden.sarif
```

A minimal GitHub Actions step:

```yaml
- run: python -m bootwarden scan build/firmware.bin --format sarif -o bootwarden.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: bootwarden.sarif }
```

## Expected result

* **VERDICT: FAIL** (exit 1) - the job fails.
* `bootwarden.sarif` is valid SARIF 2.1.0 with one result per error/warning
  finding, each carrying a rule id (e.g. `unsigned-modules`).

## How to act

Block the merge until the unsigned module is signed or removed, then let the
green PASS re-open the gate.
