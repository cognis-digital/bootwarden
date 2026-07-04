# Demo 01 - basic Secure Boot audit

This demo runs BOOTWARDEN against a tiny synthetic UEFI firmware image,
`sample_firmware.bin`, that is built by `make_sample.py`.

The sample is crafted to mirror a realistic but **mis-provisioned** firmware
so the audit fails (which is what you want a CI gate to catch):

* It contains one valid **firmware volume** (correct `_FVH` signature at
  offset 40 with a valid 16-bit header checksum).
* It provisions the Secure Boot variables **PK**, **KEK**, and **db**
  (their UTF-16LE names are embedded), but **omits `dbx`** (no revocation
  list).
* It embeds two PE executable modules: one **signed** (it has a non-empty
  Authenticode certificate-table data directory) and one **unsigned**
  (empty Security directory).

## Run it

```sh
python demos/01-basic/make_sample.py        # writes sample_firmware.bin
python -m bootwarden scan demos/01-basic/sample_firmware.bin
python -m bootwarden scan demos/01-basic/sample_firmware.bin --format json
```

## Expected result

* **VERDICT: FAIL** and a non-zero exit code, because at least one module is
  unsigned.
* A `[WARN]` for the missing `dbx` revocation list.
* `firmware volumes : 1`
* `modules : 2 total, 1 signed, 1 unsigned`
* Secure Boot keys show `PK=yes, KEK=yes, db=yes, dbx=NO`.

If you regenerate the sample with all four keys and only signed modules, the
verdict flips to **PASS** (exit 0).
