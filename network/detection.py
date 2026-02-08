"""
Interface and hardware detection module.

Consolidates interface type detection and hardware identification.
Uses consistent deterministic querying: read vendor:device from sysfs, then query hardware database.
Returns raw data - cleaning happens at display time.

IMPROVEMENTS:
- MEDIUM: Simplified functions instead of SysfsInterface class
- MEDIUM: Reduced logging verbosity
- LOW: Optimized USB device detection (single sysfs traversal)
"""

from pathlib import Path
from functools import lru_cache

from logging_config import get_logger
from utils.system import run_command, validate_interface_name, sanitize_for_log
from config import INTERFACE_TYPE_PATTERNS, USB_TETHER_DRIVERS
from enums import InterfaceType, DataMarker

logger = get_logger(__name__)


# ============================================================================
# Sysfs Helper Functions (optimized for USB detection)
# ============================================================================

def _get_sysfs_base_path(iface: str) -> Path:
    """Get base sysfs path for interface."""
    return Path(f"/sys/class/net/{iface}")


def _get_device_path(iface: str) -> Path | None:
    """Get resolved physical device path, or None if virtual interface."""
    device_link = _get_sysfs_base_path(iface) / "device"
    if not device_link.exists():
        return None
    return device_link.resolve()


@lru_cache(maxsize=32)
def _get_usb_info(iface: str) -> tuple[bool, str | None, tuple[str, str] | None]:
    """
    Get all USB information in a single sysfs traversal.

    LOW PRIORITY OPTIMIZATION: Instead of multiple separate functions
    (_is_usb_device, _get_usb_driver, _get_usb_ids), this function
    traverses sysfs once and returns all USB info.

    Returns:
        Tuple of (is_usb, driver, (vendor_id, product_id))

    Cached for performance (same interface may be queried multiple times).
    """
    device_path = _get_device_path(iface)
    if not device_path:
        return (False, None, None)

    # Check if on USB bus
    is_usb = '/usb' in str(device_path)
    if not is_usb:
        return (False, None, None)

    # Get USB driver while we're here
    driver = None
    driver_path = device_path / "driver"
    if driver_path.exists():
        driver = driver_path.resolve().name

    # Get USB IDs by traversing up the tree
    usb_ids = None
    current_path = device_path

    while current_path and current_path != Path('/'):
        vendor_file = current_path / "idVendor"
        product_file = current_path / "idProduct"

        if vendor_file.exists() and product_file.exists():
            try:
                vendor_id = vendor_file.read_text().strip()
                product_id = product_file.read_text().strip()
                usb_ids = (vendor_id, product_id)
                break
            except Exception:
                break

        current_path = current_path.parent

    return (is_usb, driver, usb_ids)


def _is_usb_device(iface: str) -> bool:
    """Check if interface is on USB bus."""
    is_usb, _, _ = _get_usb_info(iface)
    return is_usb


def _get_usb_driver(iface: str) -> str | None:
    """Get USB driver name, or None if not USB device."""
    _, driver, _ = _get_usb_info(iface)
    return driver


def _get_usb_ids(iface: str) -> tuple[str, str] | None:
    """
    Read USB vendor:product IDs from sysfs.

    Returns tuple of (vendor_id, product_id) or None.
    """
    _, _, usb_ids = _get_usb_info(iface)
    return usb_ids


def _is_wireless(iface: str) -> bool:
    """Check if interface is wireless (has phy80211)."""
    return (_get_sysfs_base_path(iface) / "phy80211").exists()


def _get_pci_ids(iface: str) -> tuple[str, str] | None:
    """
    Read PCI vendor:device IDs from sysfs.

    Returns tuple of (vendor_id, device_id) or None.
    """
    device_path = _get_device_path(iface)
    if not device_path:
        return None

    vendor_file = device_path / "vendor"
    device_file = device_path / "device"

    if not (vendor_file.exists() and device_file.exists()):
        return None

    try:
        vendor_id = vendor_file.read_text().strip().replace('0x', '')
        device_id = device_file.read_text().strip().replace('0x', '')
        return (vendor_id, device_id)
    except Exception:
        return None


# ============================================================================
# Interface Detection
# ============================================================================

def get_interface_list() -> list[str]:
    """
    Get list of all network interfaces from kernel.

    Validates all interface names before returning.
    """
    output = run_command(["ip", "-o", "link", "show"])
    if not output:
        logger.warning("Failed to get interface list")
        return []

    interfaces = []
    for line in output.split("\n"):
        if line and len(parts := line.split(":", 2)) >= 2:
            iface = parts[1].strip()

            if validate_interface_name(iface):
                interfaces.append(iface)
            else:
                logger.warning("Invalid interface: %s", sanitize_for_log(iface))

    logger.debug("Found %d interfaces: %s", len(interfaces), ", ".join(interfaces))
    return interfaces


def is_usb_tethered_device(iface: str) -> bool:
    """
    Determine if interface is a USB-tethered device.

    Checks driver name against known USB tethering drivers.

    OPTIMIZED: Uses _get_usb_info() which caches results.
    """
    if not _is_usb_device(iface):
        return False

    driver = _get_usb_driver(iface)
    if driver and driver in USB_TETHER_DRIVERS:
        logger.debug("[%s] USB tether: %s", sanitize_for_log(iface), sanitize_for_log(driver))
        return True

    return False


def detect_interface_type(iface_name: str, verbose: bool = False) -> InterfaceType:  # pylint: disable=unused-argument
    """
    Detect network interface type.

    Priority (most to least deterministic):
    1. Explicit loopback check
    2. USB tethering via sysfs driver
    3. VPN keyword in name
    4. Wireless via phy80211
    5. Kernel link type
    6. Name prefix patterns
    """
    if iface_name == "lo":
        return InterfaceType.LOOPBACK

    if not validate_interface_name(iface_name):
        logger.error("Invalid interface: %s", sanitize_for_log(iface_name))
        return InterfaceType.UNKNOWN

    if is_usb_tethered_device(iface_name):
        logger.debug("[%s] Type: tether", sanitize_for_log(iface_name))
        return InterfaceType.TETHER

    if "vpn" in iface_name.lower():
        logger.debug("[%s] Type: VPN", sanitize_for_log(iface_name))
        return InterfaceType.VPN

    if _is_wireless(iface_name):
        logger.debug("[%s] Type: wireless", sanitize_for_log(iface_name))
        return InterfaceType.WIRELESS

    output = run_command(["ip", "-d", "link", "show", iface_name])
    if output:
        output_lower = output.lower()

        if "wireguard" in output_lower:
            logger.debug("[%s] Type: VPN (WireGuard)", sanitize_for_log(iface_name))
            return InterfaceType.VPN

        if "tun" in output_lower or "tap" in output_lower:
            logger.debug("[%s] Type: VPN (TUN/TAP)", sanitize_for_log(iface_name))
            return InterfaceType.VPN

        if "veth" in output_lower:
            return InterfaceType.VIRTUAL

        if "bridge" in output_lower:
            return InterfaceType.BRIDGE

    for prefix, iface_type in INTERFACE_TYPE_PATTERNS.items():
        if iface_name.startswith(prefix):
            logger.debug("[%s] Type: %s", sanitize_for_log(iface_name), iface_type)
            return InterfaceType(iface_type)

    logger.warning("[%s] Type: unknown", sanitize_for_log(iface_name))
    return InterfaceType.UNKNOWN


# ============================================================================
# Hardware Detection
# ============================================================================

def get_pci_device_name(iface: str) -> str | None:
    """
    Get PCI device name from hardware database.

    Reads vendor:device IDs from sysfs, queries lspci database.
    Returns raw device name.
    """
    pci_ids = _get_pci_ids(iface)
    if not pci_ids:
        return None

    vendor_id, device_id = pci_ids

    lspci_output = run_command(["lspci", "-d", f"{vendor_id}:{device_id}"])
    if not lspci_output:
        return None

    lines = lspci_output.strip().split('\n')
    if not lines:
        return None

    if len(parts := lines[0].split(':', 2)) >= 3:
        device_name = parts[2].strip()
        logger.debug("[%s] Device: %s", sanitize_for_log(iface), sanitize_for_log(device_name))
        return device_name

    return None


def get_usb_device_name(iface: str) -> str | None:
    """
    Get USB device name from hardware database.

    Reads vendor:product IDs from sysfs, queries lsusb database.
    Returns raw device name.

    OPTIMIZED: Uses _get_usb_info() which caches USB information.
    """
    if not _is_usb_device(iface):
        return None

    usb_ids = _get_usb_ids(iface)
    if not usb_ids:
        return None

    vendor_id, product_id = usb_ids

    lsusb_output = run_command(["lsusb", "-d", f"{vendor_id}:{product_id}"])
    if not lsusb_output:
        return None

    lines = lsusb_output.strip().split('\n')
    if not lines:
        return None

    line = lines[0]

    if "ID " not in line:
        return None

    id_part = line.split("ID ", 1)[1]
    parts = id_part.split(None, 1)

    if len(parts) < 2:
        return None

    device_name = parts[1]
    logger.debug("[%s] Device: %s", sanitize_for_log(iface), sanitize_for_log(device_name))
    return device_name


def get_device_name(iface_name: str, iface_type: InterfaceType | str, verbose: bool = False) -> str:  # pylint: disable=unused-argument
    """
    Get hardware device name for network interface.

    Approach:
    - Virtual interfaces (loopback, VPN): Return DataMarker.NOT_AVAILABLE
    - PCI devices: Query lspci database
    - USB devices: Query lsusb database

    All names returned raw - cleaning at display time.
    """
    # Convert to InterfaceType enum for comparison if needed
    if isinstance(iface_type, InterfaceType):
        iface_type_enum = iface_type
    else:
        try:
            iface_type_enum = InterfaceType(str(iface_type))
        except ValueError:
            iface_type_enum = InterfaceType.UNKNOWN

    if iface_type_enum == InterfaceType.LOOPBACK:
        return DataMarker.NOT_AVAILABLE

    if iface_type_enum == InterfaceType.VPN:
        device_path = _get_device_path(iface_name)
        if device_path:
            if device_name := get_pci_device_name(iface_name):
                return device_name
        return DataMarker.NOT_AVAILABLE

    if iface_type_enum == InterfaceType.TETHER:
        return get_usb_device_name(iface_name) or "USB Tethered Device"

    # Default: try PCI device
    return get_pci_device_name(iface_name) or DataMarker.NOT_AVAILABLE
