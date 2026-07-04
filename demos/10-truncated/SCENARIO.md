# Demo 10 - a truncated / failed flash read (FAIL: too small)

**Where this comes from.** A flash-read aborted partway and produced a tiny
stub file. Auditing it should fail loudly rather than silently "passing" an
empty image.

**What's in the image.**
* Just 22 bytes - far smaller than any real UEFI image.

## Run it

```sh
python -m bootwarden scan demos/10-truncated/firmware.bin
python -m bootwarden scan demos/10-truncated/firmware.bin --format json | jq .findings
```

## Expected result

* **VERDICT: FAIL** (exit 1).
* `[FAIL] Image is too small to be UEFI firmware.`

## How to act

Re-dump the full flash. Check your reader's size against the chip's datasheet
(e.g. 16 MB / 32 MB) so you know the capture is complete before auditing.
