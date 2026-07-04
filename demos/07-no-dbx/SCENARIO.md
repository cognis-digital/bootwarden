# Demo 07 - provisioned but no revocation list (PASS, with a warning)

**Where this comes from.** An OEM enrolled PK, KEK, and db but never shipped a
**dbx** revocation database. Secure Boot still enforces signatures, but known
bad binaries (think the BlackLotus-class revocations) are not blocked.

**What's in the image.**
* One valid firmware volume.
* **PK, KEK, db present; dbx absent.**
* One signed PE module.

## Run it

```sh
python -m bootwarden scan demos/07-no-dbx/firmware.bin
python -m bootwarden scan demos/07-no-dbx/firmware.bin --format json | jq '.secureboot_vars'
```

## Expected result

* **VERDICT: PASS** (exit 0) - no error-level findings...
* ...but a `[WARN] No revocation list (dbx) found; known-bad binaries are not blocked.`
* `Secure Boot keys : PK=yes, KEK=yes, db=yes, dbx=NO`.

## How to act

PASS here is not "perfect." Push the latest UEFI revocation list (dbx) so
revoked bootloaders cannot run. Treat the warning as a hardening backlog item.
