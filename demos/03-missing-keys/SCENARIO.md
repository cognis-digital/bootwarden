# Demo 03 - Secure Boot never provisioned (FAIL: missing keys)

**Where this comes from.** A fleet auditor pulls firmware off a batch of
refurbished mini-PCs. The factory image was flashed but the Secure Boot
key-enrollment step was skipped, so the platform will boot anything.

**What's in the image.**
* One valid firmware volume.
* Only **PK** and **KEK** are present - **db and dbx are missing**.
* One signed PE module.

## Run it

```sh
python -m bootwarden scan demos/03-missing-keys/firmware.bin
python -m bootwarden scan demos/03-missing-keys/firmware.bin --format json
```

## Expected result

* **VERDICT: FAIL** (exit 1).
* `[FAIL] Missing required Secure Boot key variable(s): db. Secure Boot is not provisioned.`
* `[WARN]` for the missing `dbx` revocation list.
* `Secure Boot keys : PK=yes, KEK=yes, db=NO, dbx=NO`.

## How to act

Quarantine the batch. Re-run the OEM key-enrollment (`KeyEnroll` / vendor
provisioning tool) so PK, KEK, **db**, and **dbx** are all written, then
re-scan until the verdict is PASS.
