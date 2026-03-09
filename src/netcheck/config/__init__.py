"""Configuration constants for netcheck.

Single source of truth for all tuneable values.  Production code imports
from here rather than embedding literals.

``VERSION``
    Canonical version string for the tool.  Imported by the CLI for
    ``--version`` output and by the JSON export layer.

``PUBLIC_DNS_SERVERS``
    The three well-known public resolver families.  Used by the DNS leak
    detector to distinguish between "leaking to ISP" (bad) and "using a
    public resolver" (suboptimal but not an ISP leak).

``VPN_NAME_PREFIXES``
    Interface name prefixes that unambiguously indicate a VPN tunnel without
    requiring a sysfs or kernel query.

``IPINFO_URL`` / ``IPINFO_IPV6_URL``
    Endpoint URLs for the ipinfo.io API.  The IPv4 URL uses the default
    endpoint (always returns an IPv4-sourced response); the IPv6 URL forces
    an IPv6 source.

``TIMEOUT_SECONDS``
    Maximum seconds to wait for a single HTTP request or system command.

``RETRY_ATTEMPTS``
    Number of attempts for the IPv4 egress query.  IPv6 is always
    single-attempt (fail-fast, optional data).

``RETRY_BACKOFF_FACTOR``
    Multiplier for exponential backoff between retry attempts.
    Sleep between attempt n and n+1 is ``RETRY_BACKOFF_FACTOR * 2 ** n``
    seconds.
"""

from typing import Final

VERSION: Final[str] = "1.1.0"

# Last reviewed: 2026-03-01.  Add new resolvers as major public providers
# emerge.  Unknown servers are classified WARN rather than PUBLIC, which is
# the conservative failure mode: it prompts investigation rather than
# silently passing something unrecognised.
PUBLIC_DNS_SERVERS: Final[frozenset[str]] = frozenset(
    {
        # Cloudflare
        "1.1.1.1",
        "1.0.0.1",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        # Google
        "8.8.8.8",
        "8.8.4.4",
        "2001:4860:4860::8888",
        "2001:4860:4860::8844",
        # Quad9
        "9.9.9.9",
        "149.112.112.112",
        "2620:fe::fe",
        "2620:fe::9",
    }
)

VPN_NAME_PREFIXES: Final[tuple[str, ...]] = ("tun", "tap", "wg", "ppp")

IPINFO_URL: Final[str] = "https://ipinfo.io/json"
IPINFO_IPV6_URL: Final[str] = "https://v6.ipinfo.io/json"

TIMEOUT_SECONDS: Final[int] = 10
RETRY_ATTEMPTS: Final[int] = 3
RETRY_BACKOFF_FACTOR: Final[float] = 1.0
