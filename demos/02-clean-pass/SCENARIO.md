# Demo 02 - a healthy, fully-provisioned image (PASS)

**Where this comes from.** A QA engineer dumps the SPI flash of a
just-reflashed reference board with a vendor flashing tool and wants a one-line
confirmation that Secure Boot was provisioned correctly before the unit ships.

**What's in the image.**
* One valid firmware volume (`_FVH` with a correct header checksum).
* All four Secure Boot variables present: **PK, KEK, db, dbx**.
* Two PE modules, **both signed** (each carries an Authenticode certificate
  table).

## Run it

```sh
python -m bootwarden scan demos/02-clean-pass/firmware.bin
python -m bootwarden scan demos/02-clean-pass/firmware.bin --format json | jq .verdict
```

## Expected result

* **VERDICT: PASS** and **exit code 0**.
* `Secure Boot keys : PK=yes, KEK=yes, db=yes, dbx=yes`.
* `modules : 2 total, 2 signed, 0 unsigned`.
* No `[FAIL]` and no `[WARN]` lines.

## How to act

This is your green baseline. Wire the exact command into the line's
end-of-line test so any future image that loses a key or ships an unsigned
module turns the gate red.
