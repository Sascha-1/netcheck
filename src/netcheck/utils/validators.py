"""Input validation and parsing utilities for netcheck.

All functions follow the parse-don't-validate convention: they return the
validated value on success or ``None`` on failure.  This eliminates the
two-step pattern of checking a boolean and then using the raw value, which
is a common source of bugs where the check is accidentally bypassed.

Example usage::

    ip = parse_ipv4(raw_string)   # str | None -- no intermediate bool needed
    if ip is not None:
        ...                       # ip is guaranteed to be a valid IPv4 here
"""

import ipaddress
import re
from typing import Final

_INTERFACE_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9._:@-]+$")
_MAX_INTERFACE_NAME_LENGTH: Final[int] = 64


def parse_ipv4(address: str) -> str | None:
    """Return ``address`` if it is a valid IPv4 address, else ``None``.

    Args:
        address: String to validate.

    Returns:
        The original string if it is a valid IPv4 address, ``None`` otherwise.
    """
    try:
        ipaddress.IPv4Address(address)
        return address
    except ValueError:
        return None


def parse_ipv6(address: str) -> str | None:
    """Return ``address`` if it is a valid IPv6 address, else ``None``.

    Zone identifiers (e.g. ``fe80::1%eth0``) are stripped before validation
    because ``ipaddress.IPv6Address`` does not accept them.  The original
    string, including any zone identifier, is returned on success so callers
    receive the address exactly as the kernel reported it.

    Args:
        address: String to validate, optionally with a ``%zone`` suffix.

    Returns:
        The original string if it is a valid IPv6 address, ``None`` otherwise.
    """
    try:
        ipaddress.IPv6Address(address.split("%")[0])
        return address
    except ValueError:
        return None


def parse_ip(address: str) -> str | None:
    """Return ``address`` if it is a valid IPv4 or IPv6 address, else ``None``.

    IPv4 is tested first; if that fails, IPv6 is tried.

    Args:
        address: String to validate.

    Returns:
        The original string if it is a valid IP address, ``None`` otherwise.
    """
    return parse_ipv4(address) or parse_ipv6(address)


def parse_interface_name(name: str) -> str | None:
    """Return ``name`` if it is a valid Linux network interface name, else ``None``.

    Validation rules:

    - Must not be empty.
    - Must not exceed 64 characters (``IFNAMSIZ - 1``).
    - May only contain: letters, digits, ``.``, ``_``, ``:``, ``@``, ``-``.
      The ``@`` character is permitted for veth pairs (e.g. ``eth0@if2``).

    This function is used as a security gate; it must reject any string that
    could be used for command injection if passed to a subprocess.

    Args:
        name: Interface name to validate.

    Returns:
        The original string if valid, ``None`` otherwise.
    """
    if not name or len(name) > _MAX_INTERFACE_NAME_LENGTH:
        return None
    if not _INTERFACE_NAME_PATTERN.match(name):
        return None
    return name
