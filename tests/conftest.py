import os
import sys

# Make the repo root and the tests directory importable so test helpers like
# `_fwfix` and the `bootwarden` package resolve regardless of pytest's rootdir.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, ".."))
for p in (_ROOT, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)
