#!/usr/bin/env bash
# Offline tests for the shell port. Builds tiny fixtures with python3 (stdlib)
# and asserts the script's verdict + JSON fields. No network.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCAN="$HERE/bootwarden.sh"
TMP="$HERE/.testtmp"
rm -rf "$TMP"; mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT
PY3="$(command -v python3 || command -v python)"
fail=0

winpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

mkfw() { # $1=outfile  $2=python-kind-literal
  "$PY3" - "$(winpath "$1")" <<PY
import sys, struct
def fv():
    h=56; b=bytearray(h)
    b[16:32]=bytes(range(16)); b[40:44]=b"_FVH"
    struct.pack_into("<H",b,48,h); b[55]=2
    t=0
    for i in range(0,h,2): t=(t+struct.unpack_from("<H",b,i)[0])&0xFFFF
    struct.pack_into("<H",b,50,(-t)&0xFFFF)
    return bytes(b)+b"\xff"*0x100
def var(n): return n.encode("utf-16-le")+b"\x00\x00"
def vars(dbx):
    o=b"".join(var(n)+b"\x00"*16 for n in ("PK","KEK","db"))
    return o+(var("dbx") if dbx else b"")
kind=$2
if kind=="clean": data=fv()+vars(True)
elif kind=="nofv": data=vars(True)+b"\x00"*64
elif kind=="missing": data=fv()+var("PK")+b"\x00"*64
else: data=b"MZ"
open(sys.argv[1],"wb").write(data)
PY
}

assert_contains() { # haystack needle label
  case "$1" in *"$2"*) echo "ok: $3";; *) echo "FAIL: $3 (no '$2' in: $1)"; fail=1;; esac
}

mkfw "$TMP/clean.bin" '"clean"'
out="$("$SCAN" "$TMP/clean.bin" || true)"
assert_contains "$out" '"verdict":"PASS"' "clean image passes"
assert_contains "$out" '"firmware_volume":1' "clean image has FV"
assert_contains "$out" '"PK":true' "clean image has PK"

mkfw "$TMP/nofv.bin" '"nofv"'
out="$("$SCAN" "$TMP/nofv.bin" || true)"
assert_contains "$out" '"verdict":"FAIL"' "no-FV image fails"
assert_contains "$out" 'no-firmware-volume' "no-FV finding present"

mkfw "$TMP/missing.bin" '"missing"'
out="$("$SCAN" "$TMP/missing.bin" || true)"
assert_contains "$out" 'missing-secureboot-keys' "missing keys flagged"

mkfw "$TMP/tiny.bin" '"tiny"'
out="$("$SCAN" "$TMP/tiny.bin" || true)"
assert_contains "$out" 'too-small' "tiny image flagged too-small"

[ "$fail" -eq 0 ] && { echo "ALL SHELL TESTS PASSED"; exit 0; } || { echo "SHELL TESTS FAILED"; exit 1; }
