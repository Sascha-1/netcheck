"""
External egress information module.

Queries ipinfo.io for external IP address (IPv4 and IPv6), ISP, and country information.
Returns raw data - cleaning happens at display time.
"""

import requests

from logging_config import get_logger
from models import EgressInfo
from config import IPINFO_URL, IPINFO_IPv6_URL, TIMEOUT_SECONDS

logger = get_logger(__name__)


def get_egress_info() -> EgressInfo:
    """
    Query egress information from ipinfo.io for both IPv4 and IPv6.
    
    Returns raw data without cleaning - display layer handles formatting.
    
    Returns:
        EgressInfo object with raw external IPs (IPv4/IPv6), ISP, and country.
        On failure, returns EgressInfo with all fields set to "ERR".
    """
    # Query IPv4 egress
    logger.info(f"Connecting to {IPINFO_URL}...")
    
    external_ipv4 = "ERR"
    isp = "ERR"
    country = "ERR"
    
    try:
        response = requests.get(IPINFO_URL, timeout=TIMEOUT_SECONDS)
        
        if response.status_code == 200:
            data = response.json()
            
            logger.debug("IPv4 response received, parsing data...")
            
            # Extract raw values - no cleaning here
            external_ipv4 = data.get("ip", "ERR")
            isp = data.get("org", "ERR")  # Keep raw format like "AS12345 ISP Name"
            country = data.get("country", "ERR")
            
            logger.debug(f"External IPv4: {external_ipv4}")
            logger.debug(f"ISP: {isp}")
            logger.debug(f"Country: {country}")
        else:
            logger.error(f"ipinfo.io returned status {response.status_code}")
            
    except requests.exceptions.Timeout:
        logger.error(f"Request to ipinfo.io timed out after {TIMEOUT_SECONDS}s")
        logger.info("Check your internet connection and try again")
        
    except requests.exceptions.ConnectionError:
        logger.error("Could not connect to ipinfo.io")
        logger.info("Check your internet connection and firewall settings")
        
    except requests.exceptions.RequestException as e:
        logger.error(f"IPv4 request failed: {e}")
        
    except Exception as e:
        logger.error(f"Unexpected error querying ipinfo.io: {e}")
    
    # Query IPv6 egress
    logger.info(f"Connecting to {IPINFO_IPv6_URL}...")
    
    external_ipv6 = "--"  # Default to N/A if no IPv6
    
    try:
        response = requests.get(IPINFO_IPv6_URL, timeout=TIMEOUT_SECONDS)
        
        if response.status_code == 200:
            data = response.json()
            
            logger.debug("IPv6 response received, parsing data...")
            
            external_ipv6 = data.get("ip", "--")
            
            logger.debug(f"External IPv6: {external_ipv6}")
        else:
            logger.debug(f"IPv6 query returned status {response.status_code} (IPv6 may not be available)")
            external_ipv6 = "--"
            
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        logger.debug("IPv6 query failed (IPv6 may not be available)")
        external_ipv6 = "--"
        
    except Exception as e:
        logger.debug(f"IPv6 query failed: {e}")
        external_ipv6 = "--"
    
    return EgressInfo(
        external_ip=external_ipv4,
        external_ipv6=external_ipv6,
        isp=isp,
        country=country
    )
