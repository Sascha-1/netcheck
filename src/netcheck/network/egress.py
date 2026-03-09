"""External IP and ISP information retrieval for netcheck.

Queries the ipinfo.io API to obtain the public IPv4 address, ISP, and
country for the active egress interface.  IPv6 is queried as optional
supplementary data.

The module accepts an ``HttpClient`` protocol instance rather than calling
``requests`` directly, making it fully testable without network access.

API response format (ipinfo.io)
--------------------------------
Required fields (IPv4 endpoint):
    ``ip``      -- public IPv4 address string.
    ``org``     -- ISP name with AS number prefix (e.g. ``"AS3320 Deutsche Telekom AG"``).
    ``country`` -- two-letter country code (e.g. ``"DE"``).

Optional fields (IPv6 endpoint):
    ``ip``      -- public IPv6 address string.

The ``org`` field is stored raw; the display layer strips the AS number.
"""

import logging

from netcheck.config import IPINFO_IPV6_URL, IPINFO_URL, TIMEOUT_SECONDS
from netcheck.core.enums import EgressStatus
from netcheck.core.models import EgressInfo
from netcheck.utils.http import HttpClient

logger = logging.getLogger(__name__)


def get_egress_info(client: HttpClient) -> EgressInfo:
    """Query public IP, ISP, and country from the ipinfo.io API.

    Makes two requests: one to the IPv4 endpoint (required) and one to
    the IPv6 endpoint (optional, fail-fast).  The ``HttpClient`` handles
    retries and error handling internally; this function only receives a
    clean ``HttpResponse`` or ``None``.

    Args:
        client: HTTP client used for both API requests.

    Returns:
        ``EgressInfo`` with status ``OK`` on success,
        ``EgressInfo.create_failed()`` if the IPv4 query fails or the
        response is missing required fields.
    """
    ipv4_response = client.get(IPINFO_URL, TIMEOUT_SECONDS)
    if ipv4_response is None:
        logger.debug("IPv4 egress query failed (no response from %s)", IPINFO_URL)
        return EgressInfo.create_failed()

    data = ipv4_response.json()
    if not _validate_ipv4_response(data):
        logger.debug("IPv4 egress response missing required fields: %s", list(data.keys()))
        return EgressInfo.create_failed()

    external_ip = str(data["ip"])
    isp = str(data["org"])
    country = str(data["country"])
    logger.debug("IPv4 egress: ip=%s isp=%s country=%s", external_ip, isp, country)

    ipv6_response = client.get(IPINFO_IPV6_URL, TIMEOUT_SECONDS)
    external_ipv6: str | None = None
    if ipv6_response is not None:
        ipv6_data = ipv6_response.json()
        raw_v6 = ipv6_data.get("ip")
        if isinstance(raw_v6, str) and raw_v6:
            external_ipv6 = raw_v6
            logger.debug("IPv6 egress: ip=%s", external_ipv6)
    else:
        logger.debug("IPv6 egress query failed or returned no response")

    return EgressInfo(
        status=EgressStatus.OK,
        external_ip=external_ip,
        external_ipv6=external_ipv6,
        isp=isp,
        country=country,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------
def _validate_ipv4_response(data: dict[str, object]) -> bool:
    """Return ``True`` if ``data`` contains all required ipinfo.io fields.

    Args:
        data: Parsed JSON response dict from the IPv4 endpoint.

    Returns:
        ``True`` if ``ip``, ``org``, and ``country`` are all present and
        non-empty strings, ``False`` otherwise.
    """
    for field in ("ip", "org", "country"):
        value = data.get(field)
        if not isinstance(value, str) or not value:
            return False
    return True
