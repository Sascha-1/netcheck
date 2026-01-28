"""
System utilities module.

Provides command execution and data validation functions.
Consolidates commands.py and validation.py.
"""

import re
import subprocess
from functools import cache
from config import TIMEOUT_SECONDS


def run_command(cmd: list[str]) -> str | None:
    """
    Execute a system command and return output.
    
    Args:
        cmd: Command and arguments as list
        
    Returns:
        Command output as string, or None if command fails
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=TIMEOUT_SECONDS
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None


@cache
def is_valid_ipv4(address: str) -> bool:
    """
    Validate if string is a valid IPv4 address.
    
    Cached for performance when checking same addresses repeatedly.
    
    Args:
        address: String to validate
        
    Returns:
        True if valid IPv4 address, False otherwise
    """
    if not address:
        return False
    
    # IPv4 format: 1-3 digits, dot, 1-3 digits, dot, 1-3 digits, dot, 1-3 digits
    ipv4_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    
    if not (match := re.match(ipv4_pattern, address)):
        return False
    
    # Validate each octet is 0-255
    octets = [int(x) for x in match.groups()]
    return all(0 <= octet <= 255 for octet in octets)


@cache
def is_valid_ipv6(address: str) -> bool:
    """
    Validate if string is a valid IPv6 address.
    
    Handles:
    - Full IPv6 addresses (2001:0db8:0000:0000:0000:0000:0000:0001)
    - Compressed IPv6 (2001:db8::1)
    - IPv4-mapped IPv6 (::ffff:192.0.2.1)
    - Link-local addresses (fe80::1)
    
    Cached for performance when checking same addresses repeatedly.
    
    Args:
        address: String to validate
        
    Returns:
        True if valid IPv6 address, False otherwise
    """
    if not address:
        return False
    
    # Must contain at least one colon (IPv6 characteristic)
    if ':' not in address:
        return False
    
    # Cannot start or end with single colon (except ::)
    if address.startswith(':') and not address.startswith('::'):
        return False
    if address.endswith(':') and not address.endswith('::'):
        return False
    
    # Check for IPv4-mapped IPv6 (e.g., ::ffff:192.0.2.1)
    if '.' in address:
        # Split on last occurrence of ':'
        parts = address.rsplit(':', 1)
        if len(parts) == 2:
            ipv6_part, ipv4_part = parts
            # Validate the IPv4 part
            if not is_valid_ipv4(ipv4_part):
                return False
            # Continue validating the IPv6 part
            address = ipv6_part
            # Special case: if IPv6 part is just "::", it's valid
            if address == ':':
                return True
    
    # Check for multiple :: (only one compression allowed)
    if address.count('::') > 1:
        return False
    
    # Check for three or more consecutive colons (invalid)
    if ':::' in address:
        return False
    
    # Split by ':' and validate each group
    if '::' in address:
        # Handle compression
        parts = address.split('::')
        if len(parts) != 2:
            return False
        
        left = parts[0].split(':') if parts[0] else []
        right = parts[1].split(':') if parts[1] else []
        
        # Total groups cannot exceed 8 (or 7 if IPv4-mapped)
        total_groups = len(left) + len(right)
        if total_groups >= 8:
            return False
        
        # Validate each group
        all_groups = left + right
    else:
        # No compression - must be exactly 8 groups (or 7 if IPv4-mapped)
        all_groups = address.split(':')
        expected_groups = 7 if '.' in address else 8
        if len(all_groups) != expected_groups:
            return False
    
    # Validate each group is valid hex and not too long
    for group in all_groups:
        if group:  # Empty groups are OK with ::
            # Must be 1-4 hex digits
            if not (1 <= len(group) <= 4):
                return False
            # Must be valid hex
            if not all(c in '0123456789abcdefABCDEF' for c in group):
                return False
    
    return True


@cache
def is_valid_ip(address: str) -> bool:
    """
    Validate if string is a valid IP address (IPv4 or IPv6).
    
    Cached for performance when checking same addresses repeatedly.
    
    Args:
        address: String to validate
        
    Returns:
        True if valid IP address, False otherwise
    """
    return is_valid_ipv4(address) or is_valid_ipv6(address)
