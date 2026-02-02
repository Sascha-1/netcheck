"""
System utilities module.

Provides command execution and data validation functions with security hardening.
All functions are safe for unprivileged use.
"""

import re
import subprocess
from functools import cache
from typing import Any, Optional
from config import TIMEOUT_SECONDS


VALID_INTERFACE_NAME = re.compile(r'^[a-zA-Z0-9._:-]+$')


def validate_interface_name(name: str) -> bool:
    """
    Validate interface name to prevent command injection.
    
    Prevents shell metacharacters and path separators while allowing
    standard interface names like eth0, wlp8s0, tun0, enx9a5ad1b02596.
    
    Args:
        name: Interface name to validate
        
    Returns:
        True if valid interface name, False otherwise
    """
    if not name or len(name) > 64:
        return False
    return bool(VALID_INTERFACE_NAME.match(name))


def sanitize_for_log(value: Any) -> str:
    """
    Sanitize values before logging to prevent log injection attacks.
    
    Removes control characters, ANSI escape codes, and null bytes that
    could manipulate log output or terminals.
    
    Args:
        value: Any value to be logged
        
    Returns:
        Sanitized string safe for logging
    """
    if value is None:
        return "None"
    
    text = str(value)
    
    text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
    text = text.replace('\n', ' ').replace('\r', ' ')
    
    if len(text) > 200:
        text = text[:197] + "..."
    
    return text


def run_command(cmd: list[str]) -> Optional[str]:
    """
    Execute a system command and return output.
    
    Security: Uses shell=False to prevent shell injection.
    Interface names should be pre-validated with validate_interface_name().
    
    Args:
        cmd: Command and arguments as list (not string)
        
    Returns:
        Command output as string, or None if command fails
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=TIMEOUT_SECONDS,
            shell=False
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
    
    ipv4_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    
    match = re.match(ipv4_pattern, address)
    if not match:
        return False
    
    octets = [int(x) for x in match.groups()]
    return all(0 <= octet <= 255 for octet in octets)


@cache
def is_valid_ipv6(address: str) -> bool:
    """
    Validate if string is a valid IPv6 address.
    
    Handles full IPv6 addresses, compressed IPv6, IPv4-mapped IPv6,
    and link-local addresses.
    
    Cached for performance when checking same addresses repeatedly.
    
    Args:
        address: String to validate
        
    Returns:
        True if valid IPv6 address, False otherwise
    """
    if not address:
        return False
    
    if ':' not in address:
        return False
    
    if address.startswith(':') and not address.startswith('::'):
        return False
    if address.endswith(':') and not address.endswith('::'):
        return False
    
    if '.' in address:
        parts = address.rsplit(':', 1)
        if len(parts) == 2:
            ipv6_part, ipv4_part = parts
            if not is_valid_ipv4(ipv4_part):
                return False
            address = ipv6_part
            if address == '::':
                return True
    
    if address.count('::') > 1:
        return False
    
    if ':::' in address:
        return False
    
    if '::' in address:
        parts = address.split('::')
        if len(parts) != 2:
            return False
        
        left = parts[0].split(':') if parts[0] else []
        right = parts[1].split(':') if parts[1] else []
        
        total_groups = len(left) + len(right)
        if total_groups >= 8:
            return False
        
        all_groups = left + right
    else:
        all_groups = address.split(':')
        expected_groups = 7 if '.' in address else 8
        if len(all_groups) != expected_groups:
            return False
    
    for group in all_groups:
        if group:
            if not (1 <= len(group) <= 4):
                return False
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
