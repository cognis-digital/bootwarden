# Demo 06 - the dump isn't UEFI firmware at all (FAIL)

**Where this comes from.** An analyst grabbed a flash region from an embedded
device and isn't sure it's the UEFI image - it might be a coprocessor blob, a
config partition, or a bad dump. BOOTWARDEN should refuse to bless it.

**What's in the image.**
* 8 KB of structured-but-non-UEFI bytes: **no `_FVH` firmware volume**, no
  Secure Boot variables, no PE/TE modules.

## Run it

```sh
python -m bootwarden scan demos/06-not-uefi/blob.bin
python -m bootwarden scan demos/06-not-uefi/blob.bin --format json | jq .findings
```

## Expected result

* **VERDICT: FAIL** (exit 1).
* `[FAIL] No valid EFI firmware volume (_FVH) found - not a UEFI image?`
* `[FAIL] Missing required Secure Boot key variable(s) ...`.
* `[WARN] No EFI executable modules detected.`

## How to act

Re-dump from the correct flash region (or chip) and confirm you captured the
BIOS region rather than ME/EC/config partitions before auditing.
