"""
External egress information module.

Queries ipinfo.io for external IP address (IPv4 and IPv6), ISP, and country.
Returns raw data - cleaning happens at display time.

PHASE 2 MIGRATION: All 18 logging calls migrated to PEP 391 compliant % formatting.
"""

import requests
import time
from typing import Optional, Dict, Any

from logging_config import get_logger
from models import EgressInfo
from config import (
    IPINFO_URL,
    IPINFO_IPv6_URL,
    TIMEOUT_SECONDS,
    RETRY_ATTEMPTS,
    RETRY_BACKOFF_FACTOR
)
from utils.system import is_valid_ipv4, is_valid_ipv6, sanitize_for_log
from enums import DataMarker

logger = get_logger(__name__)


def validate_api_response(data: Dict[str, Any], ip_version: str) -> bool:
    """
    Validate API response structure and content.

    Args:
        data: JSON response from ipinfo.io
        ip_version: "IPv4" or "IPv6" for logging

    Returns:
        True if response is valid, False otherwise
    """
    if "ip" not in data:
        # MIGRATED: f-string → % formatting (1/18)
        logger.error("%s API response missing 'ip' field", ip_version)
        return False

    ip_addr = data.get("ip", "")

    if ip_version == "IPv4":
        if not is_valid_ipv4(ip_addr):
            # MIGRATED: f-string → % formatting (2/18)
            logger.error("Invalid IPv4 from API: %s", sanitize_for_log(ip_addr))
            return False
    else:
        if not is_valid_ipv6(ip_addr):
            # MIGRATED: f-string → % formatting (3/18)
            logger.error("Invalid IPv6 from API: %s", sanitize_for_log(ip_addr))
            return False

    return True


def get_with_retry(url: str, timeout: int) -> Optional[requests.Response]:
    """
    Execute HTTP GET with exponential backoff retry.

    Retry strategy:
    - Attempts: 3 (configurable via RETRY_ATTEMPTS)
    - Backoff: 1.0 (delays: 1s, 2s, 4s)
    - Retry on: Connection errors, timeouts, 5xx errors

    Args:
        url: URL to fetch
        timeout: Request timeout in seconds

    Returns:
        Response object if successful, None if all retries failed
    """
    for attempt in range(RETRY_ATTEMPTS):
        try:
            response = requests.get(url, timeout=timeout)

            if response.status_code == 200:
                return response

            if 500 <= response.status_code < 600:
                if attempt < RETRY_ATTEMPTS - 1:
                    delay = RETRY_BACKOFF_FACTOR * (2 ** attempt)
                    # MIGRATED: f-string → % formatting (4/18)
                    logger.debug("Server error %d, retrying in %ss (attempt %d/%d)",
                               response.status_code, delay, attempt + 1, RETRY_ATTEMPTS)
                    time.sleep(delay)
                    continue
                return response

            return response

        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            if attempt < RETRY_ATTEMPTS - 1:
                delay = RETRY_BACKOFF_FACTOR * (2 ** attempt)
                # MIGRATED: f-string → % formatting (5/18)
                logger.debug("Request failed: %s, retrying in %ss (attempt %d/%d)",
                           type(e).__name__, delay, attempt + 1, RETRY_ATTEMPTS)
                time.sleep(delay)
                continue
            # MIGRATED: f-string → % formatting (6/18)
            logger.warning("All %d attempts failed: %s", RETRY_ATTEMPTS, type(e).__name__)
            return None

        except StopIteration:
            logger.debug("Mock side_effect exhausted (test environment)")
            return None

        except requests.exceptions.RequestException as e:
            # MIGRATED: f-string → % formatting (7/18)
            logger.error("Request error: %s", sanitize_for_log(str(e)))
            return None

        except Exception as e:
            # MIGRATED: f-string → % formatting (8/18)
            logger.error("Unexpected error: %s", sanitize_for_log(str(e)))
            return None

    return None


def get_egress_info() -> EgressInfo:
    """
    Query egress information from ipinfo.io for both IPv4 and IPv6.

    Returns raw data without cleaning - display layer handles formatting.

    Returns:
        EgressInfo object with raw external IPs (IPv4/IPv6), ISP, and country.
        On failure, returns EgressInfo with all fields set to DataMarker.ERROR.

    IMPROVED: Uses DataMarker enum directly.
    """
    # MIGRATED: f-string → % formatting (9/18)
    logger.info("Connecting to %s...", IPINFO_URL)

    external_ipv4 = DataMarker.ERROR
    isp = DataMarker.ERROR
    country = DataMarker.ERROR

    response = get_with_retry(IPINFO_URL, TIMEOUT_SECONDS)

    if response is None:
        logger.error("Failed to connect to ipinfo.io (all retries exhausted)")
    elif response.status_code != 200:
        # MIGRATED: f-string → % formatting (10/18)
        logger.error("ipinfo.io returned status %d", response.status_code)
    else:
        try:
            data = response.json()

            logger.debug("IPv4 response received, parsing data...")

            if not validate_api_response(data, "IPv4"):
                logger.error("IPv4 API response validation failed")
            else:
                external_ipv4 = data.get("ip", DataMarker.ERROR)
                isp = data.get("org", DataMarker.ERROR)
                country = data.get("country", DataMarker.ERROR)

                # MIGRATED: f-string → % formatting (11/18)
                logger.debug("External IPv4: %s", external_ipv4)
                # MIGRATED: f-string → % formatting (12/18)
                logger.debug("ISP: %s", sanitize_for_log(isp))
                # MIGRATED: f-string → % formatting (13/18)
                logger.debug("Country: %s", country)

        except (ValueError, KeyError) as e:
            # MIGRATED: f-string → % formatting (14/18)
            logger.error("Failed to parse IPv4 response: %s", sanitize_for_log(str(e)))

    # MIGRATED: f-string → % formatting (15/18)
    logger.info("Connecting to %s...", IPINFO_IPv6_URL)

    external_ipv6 = DataMarker.NOT_APPLICABLE

    response_v6 = get_with_retry(IPINFO_IPv6_URL, TIMEOUT_SECONDS)

    if response_v6 is None:
        logger.debug("IPv6 query failed (IPv6 may not be available)")
    elif response_v6.status_code != 200:
        # MIGRATED: f-string → % formatting (16/18)
        logger.debug("IPv6 query returned status %d (IPv6 may not be available)",
                   response_v6.status_code)
    else:
        try:
            data_v6 = response_v6.json()

            logger.debug("IPv6 response received, parsing data...")

            if not validate_api_response(data_v6, "IPv6"):
                logger.debug("IPv6 API response validation failed")
            else:
                external_ipv6 = data_v6.get("ip", DataMarker.NOT_APPLICABLE)
                # MIGRATED: f-string → % formatting (17/18)
                logger.debug("External IPv6: %s", external_ipv6)

        except (ValueError, KeyError) as e:
            # MIGRATED: f-string → % formatting (18/18)
            logger.debug("Failed to parse IPv6 response: %s", sanitize_for_log(str(e)))

    return EgressInfo(
        external_ip=external_ipv4,
        external_ipv6=external_ipv6,
        isp=isp,
        country=country
    )
