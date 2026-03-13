"""Pre-flight availability check for external commands required by netcheck.

netcheck depends on five system commands.  This module verifies that all
five are present in PATH before the collection run begins.  A missing tool
produces a single, actionable error message rather than a cascade of silent
per-interface failures or misleading ``DataStatus.ERROR`` entries buried in
debug output.

Why check before running
------------------------
Each collection sub-module treats a missing command as a ``DataStatus.ERROR``
on the affected interface field and continues.  That graceful degradation is
appropriate for *optional* tools (e.g. ``lspci`` unavailable means no PCI
device name, not a broken run).  But none of the five tools here is optional:
without ``ip`` there are no interfaces; without ``resolvectl`` there are no
DNS records; without ``mmcli`` cellular interfaces lose hardware device
identification and modem state (detection by ``ww`` name prefix still fires,
but no ModemManager record backs it); without
``lspci`` and ``lsusb`` hardware identification is entirely absent.  Failing
before collection gives the user one clear diagnosis instead of five opaque
data-absent columns.

Package names and target distribution
--------------------------------------
Package names are correct for Debian 13 (Trixie) and its derivatives,
including Linux Mint LMDE 7.  These distributions use ``apt`` as their package
manager.  The command names are stable across distributions; only the package
names differ on non-Debian systems.

Required commands and their Debian packages
-------------------------------------------
===========  ============  =====================================================
Command      Package       Purpose
===========  ============  =====================================================
ip           iproute2      Link enumeration, address queries, route inspection
resolvectl   systemd       Per-interface DNS configuration via systemd-resolved
mmcli        modemmanager  ModemManager query for cellular/WWAN interfaces
lspci        pciutils      PCI device ID to human-readable name resolution
lsusb        usbutils      USB device ID to human-readable name resolution
===========  ============  =====================================================
"""

import dataclasses
from collections.abc import Callable
from typing import NamedTuple

from netcheck.utils.command import command_exists


class _CommandSpec(NamedTuple):
    """Registry entry for a single required external command.

    ``name`` is the bare executable name as passed to ``shutil.which``.
    ``package`` is the Debian package that provides the command.

    This type is internal.  Only ``MissingCommand`` (the result type for
    absent commands) is part of the public API.
    """

    name: str
    package: str


# Complete list of external commands that netcheck requires.
# Order is preserved in error messages: list the most fundamental tools first
# so the most actionable items appear at the top when multiple are missing.
_REQUIRED_COMMANDS: tuple[_CommandSpec, ...] = (
    _CommandSpec("ip",         "iproute2"),
    _CommandSpec("resolvectl", "systemd"),
    _CommandSpec("mmcli",      "modemmanager"),
    _CommandSpec("lspci",      "pciutils"),
    _CommandSpec("lsusb",      "usbutils"),
)


@dataclasses.dataclass(frozen=True)
class MissingCommand:
    """A required command that was not found in PATH.

    Produced by ``check_required_commands`` for each absent tool.  Carries
    both the command name (what the user tried to run) and the Debian package
    name (what to install to fix it).

    Attributes:
        name: Bare command name, e.g. ``"lspci"``.
        package: Debian package that provides the command, e.g. ``"pciutils"``.
    """

    name: str
    package: str


def check_required_commands(
    checker: Callable[[str], bool] = command_exists,
) -> list[MissingCommand]:
    """Return a list of required commands that are absent from PATH.

    Checks every entry in ``_REQUIRED_COMMANDS`` using ``checker`` and
    returns a ``MissingCommand`` instance for each command that is not found.
    An empty list means all required tools are available.

    The ``checker`` parameter exists to make this function testable without
    spawning real subprocesses or patching global state.  Production code uses
    the default (``command_exists``, backed by ``shutil.which``); tests pass a
    lambda that returns a predetermined ``True`` or ``False`` per command name.

    Args:
        checker: Callable that accepts a command name and returns ``True`` if
                 the command is available in PATH.  Defaults to
                 ``command_exists``.

    Returns:
        A list of ``MissingCommand`` instances, one per absent command, in the
        same order as ``_REQUIRED_COMMANDS``.  Empty when all commands are
        present.
    """
    missing: list[MissingCommand] = []
    for spec in _REQUIRED_COMMANDS:
        if not checker(spec.name):
            missing.append(MissingCommand(name=spec.name, package=spec.package))
    return missing


def format_missing_commands(missing: list[MissingCommand]) -> str:
    """Format a human-readable error message for absent commands.

    Produces a multi-line string beginning with ``"netcheck:"`` that lists
    each missing command and its Debian package, followed by a combined
    ``apt install`` command that fixes all absences in one step.

    The install line deduplicates package names while preserving order, so
    if two commands share a package it appears only once.

    Args:
        missing: Non-empty list of ``MissingCommand`` instances as returned
                 by ``check_required_commands``.  Behaviour is undefined for
                 an empty list; callers must not invoke this function when
                 ``check_required_commands`` returns ``[]``.

    Returns:
        Formatted string ready to be written to stderr.
    """
    # Compute column width from the longest command name for alignment.
    width = max(len(m.name) for m in missing)

    lines: list[str] = [
        "netcheck: the following required commands are not available:",
        "",
    ]
    for m in missing:
        lines.append(f"  {m.name:<{width}}  (package: {m.package})")

    # Deduplicate package names, preserving the order in which they appear.
    # dict.fromkeys() is the idiomatic O(n) deduplication with preserved order.
    packages = " ".join(dict.fromkeys(m.package for m in missing))
    lines += [
        "",
        "Install with:",
        f"  sudo apt install {packages}",
    ]
    return "\n".join(lines)
