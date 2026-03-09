"""Shared utilities for netcheck.

This package provides infrastructure used across all other packages.  It has
no dependencies on any other netcheck package.

Exported names
--------------
From ``command``:
    ``CommandRunner``        -- Protocol for injectable command execution.
    ``SystemCommandRunner``  -- Production subprocess implementation.
    ``command_exists``       -- Check whether a command is in ``PATH``.

From ``http``:
    ``HttpClient``           -- Protocol for injectable HTTP GET requests.
    ``HttpResponse``         -- Protocol for a successfully parsed HTTP response.
    ``SystemHttpClient``     -- Production requests implementation.

From ``sysfs``:
    ``SysfsReader``          -- Protocol for injectable sysfs access.
    ``SystemSysfsReader``    -- Production pathlib implementation.

From ``validators``:
    ``parse_interface_name`` -- Validate and return an interface name or ``None``.
    ``parse_ip``             -- Validate and return an IPv4/IPv6 address or ``None``.
    ``parse_ipv4``           -- Validate and return an IPv4 address or ``None``.
    ``parse_ipv6``           -- Validate and return an IPv6 address or ``None``.
"""

from netcheck.utils.command import (
    CommandRunner,
    SystemCommandRunner,
    command_exists,
)
from netcheck.utils.http import HttpClient, HttpResponse, SystemHttpClient
from netcheck.utils.sysfs import SysfsReader, SystemSysfsReader
from netcheck.utils.validators import (
    parse_interface_name,
    parse_ip,
    parse_ipv4,
    parse_ipv6,
)

__all__ = [
    # Command execution
    "CommandRunner",
    "SystemCommandRunner",
    "command_exists",
    # HTTP
    "HttpClient",
    "HttpResponse",
    "SystemHttpClient",
    # Sysfs access
    "SysfsReader",
    "SystemSysfsReader",
    # Validators
    "parse_interface_name",
    "parse_ip",
    "parse_ipv4",
    "parse_ipv6",
]
