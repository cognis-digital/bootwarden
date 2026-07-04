# Demo 04 - an unsigned DXE driver slipped into a signed image (FAIL)

**Where this comes from.** A third-party "performance" UEFI driver was merged
into an otherwise-signed image during a custom build. Secure Boot keys are all
present, but one module never got signed - exactly the gap a firmware implant
would hide behind.

**What's in the image.**
* One valid firmware volume; **all four** Secure Boot keys present.
* Three PE modules: **two signed, one unsigned**.

## Run it

```sh
python -m bootwarden scan demos/04-unsigned-driver/firmware.bin
python -m bootwarden scan demos/04-unsigned-driver/firmware.bin --format json \
  | jq '.findings[] | select(.code=="unsigned-module") | .offset'
```

## Expected result

* **VERDICT: FAIL** (exit 1).
* `[FAIL] 1 of 3 executable module(s) are unsigned ...` with the byte offset.
* An `info` `unsigned-module` finding pointing at the offending module.
* `modules : 3 total, 2 signed, 1 unsigned`.

## How to act

Use the reported offset to locate the module, identify the vendor, and either
get a signed build or remove it. Never ship an image with an unsigned executable
module on a Secure-Boot platform.
