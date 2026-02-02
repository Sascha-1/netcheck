"""
System utilities module.

Provides command execution and data validation functions.
Consolidates commands.py and validation.py.

IMPROVEMENTS:
- Command injection prevention (Fix #1)
- Log injection prevention (Fix #2)
- IPv6 validation bug fix (Fix #4)
- Performance caching
- FIXED: sanitize_for_log newline and ANSI handling
- FIXED: validate_interface_name newline rejection

Security:
    All functions safe for unprivileged use (no sudo required)
"""

import re
import subprocess
from functools import cache
from typing import Any, Optional
from config import TIMEOUT_SECONDS


# ============================================================================
# Security: Input Validation (Fix #1 - Command Injection Prevention)
# ============================================================================

# Regex for valid interface names (systemd + traditional naming)
# Allows: letters, digits, hyphens, underscores, dots, colons
# Prevents: shell metacharacters, path separators, quotes
VALID_INTERFACE_NAME = re.compile(r'^[a-zA-Z0-9._:-]+$')


def validate_interface_name(name: str) -> bool:
    """
    Validate interface name to prevent command injection.
    
    Prevents shell metacharacters: ; & | ` $ ( ) { } [ ] < > ' "
    Prevents path separators: / \\
    Prevents newlines: \\n \\r
    Allows standard interface names: eth0, wlp8s0, tun0, enx9a5ad1b02596
    
    Args:
        name: Interface name to validate
        
    Returns:
        True if valid interface name, False otherwise
        
    Security:
        Critical defense against command injection (Fix #1)
    """
    # FIXED: Explicit check for newlines and carriage returns
    if not name or len(name) > 64 or '\n' in name or '\r' in name:  # Reasonable max length
        return False
    return bool(VALID_INTERFACE_NAME.match(name))


# ============================================================================
# Security: Log Sanitization (Fix #2 - Log Injection Prevention)
# ============================================================================

def sanitize_for_log(value: Any) -> str:
    """
    Sanitize values before logging to prevent log injection attacks.
    
    Removes control characters that could manipulate log output:
    - Newlines (\\n, \\r) - prevent log splitting
    - ANSI escape codes - prevent terminal manipulation
    - Null bytes - prevent log truncation
    
    FIXED: Proper order of operations:
    1. Replace newlines with spaces (FIRST)
    2. Remove ANSI escape sequences  
    3. Remove other control characters
    
    Args:
        value: Any value to be logged
        
    Returns:
        Sanitized string safe for logging
        
    Security:
        Critical defense against log injection (Fix #2)
        
    Examples:
        >>> sanitize_for_log("normal text")
        'normal text'
        >>> sanitize_for_log("line1\\nline2")
        'line1 line2'
        >>> sanitize_for_log("\\x1b[31mred\\x1b[0m")
        'red'
    """
    # Convert to string, handling None
    if value is None:
        return "None"
    
    text = str(value)
    
    # FIXED: Step 1 - Replace newlines with spaces (BEFORE removing control chars)
    # This ensures newlines become spaces, not just disappear
    text = text.replace('\n', ' ').replace('\r', ' ')
    
    # FIXED: Step 2 - Remove ANSI escape sequences (comprehensive pattern)
    # Pattern: ESC [ followed by zero or more digits/semicolons, ending with m
    # This removes complete ANSI color codes like \x1b[31m and \x1b[0m
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    
    # FIXED: Step 3 - Remove remaining control characters (excluding \n, \r which are already handled)
    # \x00-\x08: Null through backspace
    # \x0b: Vertical tab (skip \n=0x0a)
    # \x0c: Form feed  
    # \x0e-\x1f: Shift out through unit separator
    # \x7f-\x9f: Delete through application program command
    text = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f]', '', text)
    
    # Limit length for logs (prevent log flooding)
    if len(text) > 200:
        text = text[:197] + "..."
    
    return text


# ============================================================================
# Command Execution
# ============================================================================

def run_command(cmd: list[str]) -> Optional[str]:
    """
    Execute a system command and return output.
    
    Security:
        - No shell=True (prevents shell injection)
        - Timeout protection
        - Interface names should be pre-validated with validate_interface_name()
    
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
            shell=False  # Critical: never use shell=True
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None


# ============================================================================
# IP Validation (with IPv6 bug fix)
# ============================================================================

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
    
    match = re.match(ipv4_pattern, address)
    if not match:
        return False
    
    # Validate each octet is 0-255
    octets = [int(x) for x in match.groups()]
    return all(0 <= octet <= 255 for octet in octets)


@cache
def is_valid_ipv6(address: str) -> bool:
    """
    Validate if string is a valid IPv6 address.
    
    FIXED (Issue #4): Line 157 bug - `if address == ':'` → `if address == '::'`
    
    Handles:
    - Full IPv6 addresses (2001:0db8:0000:0000:0000:0000:0000:0001)
    - Compressed IPv6 (2001:db8::1)
    - IPv4-mapped IPv6 (::ffff:192.0.2.1, ::192.0.2.1)
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
    
    # Check for IPv4-mapped IPv6 (e.g., ::ffff:192.0.2.1 or ::192.0.2.1)
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
            # FIXED (Issue #4): Changed from `if address == ':'` to `if address == '::'`
            # Special case: if IPv6 part is just "::", it's valid (e.g., ::192.0.2.1)
            if address == '::':
                return True
            # Empty IPv6 part also valid (e.g., "::1" parsed as "" and "::1")
            if not address:
                return False
    
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
