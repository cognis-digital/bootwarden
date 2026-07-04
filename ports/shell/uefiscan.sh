#!/usr/bin/env bash
# Shell port of the BOOTWARDEN core check (passive/offline).
#
# A lightweight, dependency-light triage: detect the EFI firmware-volume
# signature ("_FVH"), the UTF-16LE Secure Boot variable names (PK/KEK/db/dbx),
# and the presence of PE/TE module magics in a firmware dump you already have.
# Emits a JSON verdict. No network, no device access.
#
# Requires: a POSIX shell + `od` (or `xxd`) + `grep`. Pure local file analysis.
set -euo pipefail

usage() { echo "usage: bootwarden.sh <firmware.bin>" >&2; exit 2; }

[ $# -ge 1 ] || usage
IMG="$1"
[ -f "$IMG" ] || { echo "error: file not found: $IMG" >&2; exit 2; }

# Hex-dump the image once (lowercase, no addresses), as a single hex string.
hex() {
  if command -v xxd >/dev/null 2>&1; then
    xxd -p "$1" | tr -d '\n'
  else
    od -An -tx1 -v "$1" | tr -d ' \n'
  fi
}

HEX="$(hex "$IMG")"
SIZE=$(wc -c < "$IMG" | tr -d ' ')

contains() { case "$HEX" in *"$1"*) return 0;; *) return 1;; esac; }

# "_FVH" = 5f465648
FV=0
contains "5f465648" && FV=1

# UTF-16LE variable names, each followed by a 16-bit NUL terminator (0000).
#   'P'=50 'K'=4b -> "PK\0" = 50004b00 0000
#   'K''E''K'     -> 4b0045004b00 0000
#   'd''b'        -> 64006200 0000
#   'd''b''x'     -> 640062007800 0000
have_var() { contains "$1" && echo true || echo false; }
PK=$(have_var "50004b000000")
KEK=$(have_var "4b0045004b000000")
DB=$(have_var "640062000000")
DBX=$(have_var "6400620078000000")

# Module magics: MZ=4d5a , TE "VZ"=565a
MODS=0
contains "4d5a" && MODS=1
contains "565a" && MODS=1

VERDICT="PASS"
FINDINGS=""
add() { FINDINGS="${FINDINGS:+$FINDINGS,}\"$1\""; VERDICT="FAIL"; }

[ "$SIZE" -lt 64 ] && add "too-small"
[ "$FV" -eq 0 ] && add "no-firmware-volume"
{ [ "$PK" = false ] || [ "$KEK" = false ] || [ "$DB" = false ]; } && add "missing-secureboot-keys"

printf '{"tool":"bootwarden","verdict":"%s","firmware_volume":%s,"secureboot_vars":{"PK":%s,"KEK":%s,"db":%s,"dbx":%s},"has_modules":%s,"findings":[%s]}\n' \
  "$VERDICT" "$FV" "$PK" "$KEK" "$DB" "$DBX" "$MODS" "$FINDINGS"

[ "$VERDICT" = "PASS" ] && exit 0 || exit 1
