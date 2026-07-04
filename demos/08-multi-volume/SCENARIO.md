# Demo 08 - a multi-volume laptop image (PASS)

**Where this comes from.** A full SPI dump from a laptop typically contains
**several** firmware volumes (one per region/phase). This exercises BOOTWARDEN's
ability to enumerate more than one valid `_FVH` volume in a single image.

**What's in the image.**
* **Two** valid firmware volumes (distinct FileSystem GUIDs).
* All four Secure Boot keys present.
* Two signed PE modules.

## Run it

```sh
python -m bootwarden scan demos/08-multi-volume/firmware.bin
python -m bootwarden scan demos/08-multi-volume/firmware.bin --format json | jq '.firmware_volumes'
```

## Expected result

* **VERDICT: PASS** (exit 0).
* `firmware volumes : 2`.
* `modules : 2 total, 2 signed, 0 unsigned`.

## How to act

Record the firmware-volume count as part of your baseline. A future dump of the
same model that suddenly has a different volume count is worth investigating.
