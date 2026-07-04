# Demo 05 - a TE (Terse Executable) module in the image (FAIL)

**Where this comes from.** Early-boot SEC/PEI-phase code is frequently stored
as **TE** images rather than full PE/COFF. TE images have no Authenticode
certificate table, so BOOTWARDEN always reports them as unsigned - useful for
inventorying exactly which early-boot modules ride below the Secure Boot
signature check.

**What's in the image.**
* One valid firmware volume; all four Secure Boot keys present.
* One **TE** module (unsigned by construction) and one signed PE module.

## Run it

```sh
python -m bootwarden scan demos/05-te-module/firmware.bin
python -m bootwarden scan demos/05-te-module/firmware.bin --format json \
  | jq '.modules'
```

## Expected result

* **VERDICT: FAIL** (exit 1) - the TE module counts as unsigned.
* `modules : 2 total, 1 signed, 1 unsigned`.
* An `unsigned-module` finding for the TE image.

## How to act

TE modules are normal in the PEI phase, but you should still know which ones
exist. Confirm each TE module is a known, expected SEC/PEI component and not an
injected early-boot payload.
