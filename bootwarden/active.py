"""Authorization-gated ACTIVE mode for BOOTWARDEN.

DEFENSIVE / AUTHORIZED-USE ONLY.

BOOTWARDEN's normal mode is *passive*: it reads a firmware dump you already have
and analyses it entirely offline. This module adds an *active* capability that
pulls **live** Secure Boot state from the **local machine you own/operate** by
reading the platform's EFI variable store through the operating system
(``/sys/firmware/efi/efivars`` on Linux, or a caller-supplied provider).

It does NOT scan, probe, or connect to any remote host. The only "target" it
will ever touch is the local platform, and even that is gated:

  * OFF by default. Nothing runs unless ``authorized=True`` (CLI ``--authorized``).
  * Scope-enforced. The local hostname must appear in an explicit allowlist
    (CLI ``--target-allowlist host[,host...]`` or ``--scope-file FILE``). A host
    not in scope is refused.
  * Rate-limited. Reads are throttled (CLI ``--rate-limit N`` reads/second) so an
    active run cannot hammer a device interface.
  * Loud banner. Every active run prints an "AUTHORIZED-USE-ONLY" banner.

Tests exercise this module with an injected in-memory provider — they NEVER
read real firmware and NEVER touch a network. See ``tests/test_active.py``.
"""

from __future__ import annotations

import platform
import socket
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .core import _SECUREBOOT_VARS, _REQUIRED_VARS, Finding, AuditResult

AUTHORIZED_USE_BANNER = (
    "================================================================\n"
    " BOOTWARDEN ACTIVE MODE - AUTHORIZED USE ONLY\n"
    " Reads LIVE Secure Boot state from the LOCAL platform only.\n"
    " You must own or be explicitly authorized to inspect this host.\n"
    " No remote hosts are contacted. Defensive use only.\n"
    "================================================================"
)


class ScopeError(PermissionError):
    """Raised when an active run is attempted outside its authorized scope."""


class NotAuthorizedError(PermissionError):
    """Raised when active mode is invoked without explicit authorization."""


# A provider returns a mapping of Secure Boot variable name -> present(bool).
# The default provider reads the local OS; tests inject a fake one.
VarProvider = Callable[[], Dict[str, bool]]


@dataclass
class ActiveConfig:
    """Gate configuration for an active run. Everything defaults to *safe*."""

    authorized: bool = False
    allowlist: List[str] = field(default_factory=list)
    rate_limit: float = 2.0  # reads per second (must be > 0)
    host: Optional[str] = None  # local host identity; auto-detected if None

    def resolved_host(self) -> str:
        return self.host or socket.gethostname()


def local_hostname() -> str:
    return socket.gethostname()


def _linux_efivars_provider() -> Dict[str, bool]:
    """Read live Secure Boot variable presence from the Linux efivarfs.

    Looks for the well-known GUID-suffixed variable files. Best-effort and
    read-only; absence of the mount or a permission error simply reports the
    variable as not-present rather than raising.
    """
    import os

    base = "/sys/firmware/efi/efivars"
    present: Dict[str, bool] = {v: False for v in _SECUREBOOT_VARS}
    try:
        entries = os.listdir(base)
    except OSError:
        return present
    for v in _SECUREBOOT_VARS:
        prefix = v + "-"
        present[v] = any(e.startswith(prefix) for e in entries)
    return present


def default_provider() -> VarProvider:
    """Pick a live provider for the current OS (Linux efivarfs only today)."""
    if platform.system() == "Linux":
        return _linux_efivars_provider
    # On other platforms we have no safe read-only live source wired in yet.
    def _unsupported() -> Dict[str, bool]:
        raise RuntimeError(
            "active mode live read is only implemented on Linux "
            "(efivarfs); supply a provider explicitly otherwise"
        )
    return _unsupported


class RateLimiter:
    """Simple monotonic-clock token spacer: at most `rate` calls per second."""

    def __init__(self, rate: float, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        if rate <= 0:
            raise ValueError("rate_limit must be > 0")
        self._min_interval = 1.0 / rate
        self._clock = clock
        self._sleep = sleep
        self._last = None  # None until the first wait() has run

    def wait(self) -> None:
        now = self._clock()
        if self._last is not None:
            elapsed = now - self._last
            if elapsed < self._min_interval:
                self._sleep(self._min_interval - elapsed)
        self._last = self._clock()


def enforce_scope(cfg: ActiveConfig) -> str:
    """Validate authorization + scope. Returns the in-scope host or raises."""
    if not cfg.authorized:
        raise NotAuthorizedError(
            "active mode is OFF by default; pass --authorized to enable "
            "(authorized/defensive use only)"
        )
    if not cfg.allowlist:
        raise ScopeError(
            "active mode requires a non-empty target allowlist "
            "(--target-allowlist or --scope-file)"
        )
    host = cfg.resolved_host()
    allowed = {h.strip().lower() for h in cfg.allowlist if h.strip()}
    if host.lower() not in allowed:
        raise ScopeError(
            "host {!r} is not in the authorized scope {} - refusing".format(
                host, sorted(allowed)
            )
        )
    return host


def active_audit(
    cfg: ActiveConfig,
    provider: Optional[VarProvider] = None,
    rate_limiter: Optional[RateLimiter] = None,
) -> AuditResult:
    """Perform a gated, live, read-only Secure Boot audit of the local host.

    Raises NotAuthorizedError / ScopeError if the gates are not satisfied. On
    success, returns an AuditResult describing the live Secure Boot variable
    state (firmware-volume/module checks are not applicable to a live read).
    """
    host = enforce_scope(cfg)
    provider = provider or default_provider()
    limiter = rate_limiter or RateLimiter(cfg.rate_limit)

    result = AuditResult(path="live://{}".format(host), size=0)
    result.findings.append(
        Finding("info", "active-mode",
                "Live Secure Boot read of local host {!r} (authorized).".format(host))
    )

    limiter.wait()
    sbvars = provider()
    # Normalise to the canonical set so a partial provider still reports all.
    result.secureboot_vars = {v: bool(sbvars.get(v, False)) for v in _SECUREBOOT_VARS}

    missing = [v for v in _REQUIRED_VARS if not result.secureboot_vars.get(v)]
    if missing:
        result.findings.append(
            Finding("error", "missing-secureboot-keys",
                    "Live host is missing required Secure Boot key variable(s): "
                    + ", ".join(missing) + ".")
        )
    if not result.secureboot_vars.get("dbx"):
        result.findings.append(
            Finding("warn", "no-dbx",
                    "Live host has no revocation list (dbx); known-bad binaries "
                    "are not blocked.")
        )
    return result
