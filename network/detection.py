"""
Interface and hardware detection module.

Consolidates interface type detection and hardware identification.
Uses consistent deterministic querying: read vendor:device from sysfs, then query hardware database.
Returns raw data - cleaning happens at display time.
"""

from pathlib import Path
from functools import cached_property
from dataclasses import dataclass

from logging_config import get_logger
from utils.system import run_command, validate_interface_name, sanitize_for_log
from config import INTERFACE_TYPE_PATTERNS, USB_TETHER_DRIVERS
from enums import InterfaceType, DataMarker

logger = get_logger(__name__)


@dataclass
class SysfsInterface:
    """
    Encapsulates sysfs operations for a network interface.
    
    Provides cached properties for expensive filesystem operations.
    All hardware ID queries use consistent pattern: read from sysfs, query database.
    """
    name: str
    
    def __post_init__(self) -> None:
        """Validate interface name on construction."""
        if not validate_interface_name(self.name):
            raise ValueError(f"Invalid interface name: {self.name}")
    
    @cached_property
    def base_path(self) -> Path:
        """Base sysfs path for this interface."""
        return Path(f"/sys/class/net/{self.name}")
    
    @cached_property
    def device_path(self) -> Path | None:
        """Physical device path, or None if virtual interface."""
        path = self.base_path / "device"
        return path if path.exists() else None
    
    @cached_property
    def real_device_path(self) -> Path | None:
        """Resolved real path to device, or None if virtual."""
        return self.device_path.resolve() if self.device_path else None
    
    @cached_property
    def is_usb(self) -> bool:
        """True if device is on USB bus."""
        return bool(self.real_device_path and '/usb' in str(self.real_device_path))
    
    @cached_property
    def is_wireless(self) -> bool:
        """True if device is wireless (has phy80211)."""
        return (self.base_path / "phy80211").exists()
    
    @cached_property
    def usb_driver(self) -> str | None:
        """USB driver name, or None if not USB device."""
        if not self.real_device_path:
            return None
        
        driver_path = self.real_device_path / "driver"
        if driver_path.exists():
            return driver_path.resolve().name
        return None
    
    @cached_property
    def pci_ids(self) -> tuple[str, str] | None:
        """
        PCI vendor:device IDs from sysfs.
        
        Returns tuple of (vendor_id, device_id) or None.
        """
        if not self.real_device_path:
            return None
        
        vendor_file = self.real_device_path / "vendor"
        device_file = self.real_device_path / "device"
        
        if not (vendor_file.exists() and device_file.exists()):
            return None
        
        try:
            vendor_id = vendor_file.read_text().strip().replace('0x', '')
            device_id = device_file.read_text().strip().replace('0x', '')
            return (vendor_id, device_id)
        except Exception as e:
            logger.warning(f"Failed to read PCI IDs for {sanitize_for_log(self.name)}: {e}")
            return None
    
    @cached_property
    def usb_ids(self) -> tuple[str, str] | None:
        """
        USB vendor:product IDs from sysfs.
        
        Navigates USB device tree to find idVendor and idProduct files.
        Returns tuple of (vendor_id, product_id) or None.
        """
        if not self.real_device_path:
            return None
        
        current_path = self.real_device_path
        
        while current_path and current_path != Path('/'):
            vendor_file = current_path / "idVendor"
            product_file = current_path / "idProduct"
            
            if vendor_file.exists() and product_file.exists():
                try:
                    vendor_id = vendor_file.read_text().strip()
                    product_id = product_file.read_text().strip()
                    return (vendor_id, product_id)
                except Exception as e:
                    logger.warning(f"Failed to read USB IDs for {sanitize_for_log(self.name)}: {e}")
                    break
            
            current_path = current_path.parent
        
        return None


def get_interface_list() -> list[str]:
    """
    Get list of all network interfaces from kernel.
    
    Validates all interface names before returning.
    """
    logger.debug("Querying network interfaces via 'ip -o link show'")
    
    output = run_command(["ip", "-o", "link", "show"])
    if not output:
        logger.warning("Failed to get interface list from 'ip' command")
        return []
    
    interfaces = []
    for line in output.split("\n"):
        if line and len(parts := line.split(":", 2)) >= 2:
            iface = parts[1].strip()
            
            if validate_interface_name(iface):
                interfaces.append(iface)
            else:
                logger.warning(f"Ignoring invalid interface name: {sanitize_for_log(iface)}")
    
    logger.debug(f"Found {len(interfaces)} interfaces: {', '.join(interfaces)}")
    return interfaces


def is_usb_tethered_device(sysfs: SysfsInterface, verbose: bool = False) -> bool:
    """
    Determine if interface is a USB-tethered device.
    
    Checks driver name against known USB tethering drivers.
    """
    if not sysfs.is_usb:
        return False
    
    logger.debug(f"[{sanitize_for_log(sysfs.name)}] Device is on USB bus")
    
    if driver := sysfs.usb_driver:
        logger.debug(f"[{sanitize_for_log(sysfs.name)}] USB driver: {sanitize_for_log(driver)}")
        
        if driver in USB_TETHER_DRIVERS:
            logger.debug(f"[{sanitize_for_log(sysfs.name)}] Matched tethering driver: {sanitize_for_log(driver)}")
            return True
        
        logger.debug(f"[{sanitize_for_log(sysfs.name)}] Driver '{sanitize_for_log(driver)}' is not a tethering driver")
    
    return False


def detect_interface_type(iface_name: str, verbose: bool = False) -> str:
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
    safe_name = sanitize_for_log(iface_name)
    
    if iface_name == "lo":
        logger.debug(f"[{safe_name}] Detected as loopback")
        return str(InterfaceType.LOOPBACK)
    
    try:
        sysfs = SysfsInterface(iface_name)
    except ValueError as e:
        logger.error(f"Invalid interface name in detect_interface_type: {e}")
        return str(InterfaceType.UNKNOWN)
    
    if is_usb_tethered_device(sysfs, verbose):
        logger.debug(f"[{safe_name}] Detected as tether (USB)")
        return str(InterfaceType.TETHER)
    
    if "vpn" in iface_name.lower():
        logger.debug(f"[{safe_name}] Detected as VPN (keyword in name)")
        return str(InterfaceType.VPN)
    
    if sysfs.is_wireless:
        logger.debug(f"[{safe_name}] Detected as wireless (phy80211 present)")
        return str(InterfaceType.WIRELESS)
    
    output = run_command(["ip", "-d", "link", "show", iface_name])
    if output:
        output_lower = output.lower()
        
        if "wireguard" in output_lower:
            logger.debug(f"[{safe_name}] Detected as VPN (WireGuard)")
            return str(InterfaceType.VPN)
        
        if "tun" in output_lower or "tap" in output_lower:
            logger.debug(f"[{safe_name}] Detected as VPN (TUN/TAP)")
            return str(InterfaceType.VPN)
        
        if "veth" in output_lower:
            logger.debug(f"[{safe_name}] Detected as virtual (veth)")
            return str(InterfaceType.VIRTUAL)
        
        if "bridge" in output_lower:
            logger.debug(f"[{safe_name}] Detected as bridge")
            return str(InterfaceType.BRIDGE)
    
    for prefix, iface_type in INTERFACE_TYPE_PATTERNS.items():
        if iface_name.startswith(prefix):
            logger.debug(f"[{safe_name}] Detected as {iface_type} (systemd prefix '{prefix}')")
            return iface_type
    
    logger.warning(f"[{safe_name}] Type unknown (no detection method matched)")
    return str(InterfaceType.UNKNOWN)


def get_pci_device_name(sysfs: SysfsInterface, verbose: bool = False) -> str | None:
    """
    Get PCI device name from hardware database.
    
    Consistent query pattern:
    1. Read vendor:device IDs from sysfs
    2. Query lspci database with those IDs
    3. Return raw device name
    """
    safe_name = sanitize_for_log(sysfs.name)
    
    if not (pci_ids := sysfs.pci_ids):
        logger.debug(f"[{safe_name}] No PCI IDs found")
        return None
    
    vendor_id, device_id = pci_ids
    
    logger.debug(f"[{safe_name}] PCI ID: {vendor_id}:{device_id}")
    
    lspci_output = run_command(["lspci", "-d", f"{vendor_id}:{device_id}"])
    if not lspci_output:
        logger.error(f"lspci query failed for {safe_name} ({vendor_id}:{device_id})")
        return None
    
    lines = lspci_output.strip().split('\n')
    if not lines:
        logger.warning(f"Empty lspci output for {safe_name}")
        return None
    
    if len(parts := lines[0].split(':', 2)) >= 3:
        device_name = parts[2].strip()
        logger.debug(f"[{safe_name}] Device: {sanitize_for_log(device_name)}")
        return device_name
    
    logger.warning(f"Failed to parse lspci output for {safe_name}")
    return None


def get_usb_device_name(sysfs: SysfsInterface, verbose: bool = False) -> str | None:
    """
    Get USB device name from hardware database.
    
    Consistent query pattern:
    1. Read vendor:product IDs from sysfs
    2. Query lsusb database with those IDs
    3. Return raw device name
    """
    safe_name = sanitize_for_log(sysfs.name)
    
    if not sysfs.is_usb:
        return None
    
    logger.debug(f"[{safe_name}] USB device detected, querying lsusb...")
    
    if not (usb_ids := sysfs.usb_ids):
        logger.error(f"Could not read USB IDs from sysfs for {safe_name}")
        return None
    
    vendor_id, product_id = usb_ids
    
    logger.debug(f"[{safe_name}] USB ID: {vendor_id}:{product_id}")
    
    lsusb_output = run_command(["lsusb", "-d", f"{vendor_id}:{product_id}"])
    if not lsusb_output:
        logger.error(f"lsusb query failed for {safe_name} ({vendor_id}:{product_id})")
        return None
    
    lines = lsusb_output.strip().split('\n')
    if not lines:
        logger.warning(f"Empty lsusb output for {safe_name}")
        return None
    
    line = lines[0]
    
    if "ID " not in line:
        logger.error(f"Unexpected lsusb format for {safe_name}")
        return None
    
    id_part = line.split("ID ", 1)[1]
    parts = id_part.split(None, 1)
    
    if len(parts) < 2:
        logger.error(f"No device name in lsusb output for {safe_name}")
        return None
    
    device_name = parts[1]
    logger.debug(f"[{safe_name}] Device: {sanitize_for_log(device_name)}")
    return device_name


def get_device_name(iface_name: str, iface_type: str, verbose: bool = False) -> str:
    """
    Get hardware device name for network interface.
    
    Consistent approach:
    - Virtual interfaces (loopback, VPN): Return DataMarker.NOT_AVAILABLE
    - PCI devices: Query lspci database
    - USB devices: Query lsusb database
    
    All names returned raw - cleaning at display time.
    """
    safe_name = sanitize_for_log(iface_name)
    
    match iface_type:
        case str(InterfaceType.LOOPBACK) | InterfaceType.LOOPBACK.value:
            return str(DataMarker.NOT_AVAILABLE)
        
        case str(InterfaceType.VPN) | InterfaceType.VPN.value:
            try:
                sysfs = SysfsInterface(iface_name)
            except ValueError:
                return str(DataMarker.NOT_AVAILABLE)
            
            if sysfs.device_path:
                if device_name := get_pci_device_name(sysfs, verbose):
                    logger.debug(f"[{safe_name}] VPN has hardware device: {sanitize_for_log(device_name)}")
                    return device_name
            else:
                logger.debug(f"[{safe_name}] Virtual VPN interface")
                output = run_command(["ip", "-d", "link", "show", iface_name])
                if output and "wireguard" in output.lower():
                    logger.debug(f"[{safe_name}] VPN protocol: WireGuard")
                else:
                    logger.debug(f"[{safe_name}] VPN protocol: Generic")
            
            return str(DataMarker.NOT_AVAILABLE)
        
        case str(InterfaceType.TETHER) | InterfaceType.TETHER.value:
            try:
                sysfs = SysfsInterface(iface_name)
                return get_usb_device_name(sysfs, verbose) or "USB Tethered Device"
            except ValueError:
                return "USB Tethered Device"
        
        case _:
            try:
                sysfs = SysfsInterface(iface_name)
                return get_pci_device_name(sysfs, verbose) or str(DataMarker.NOT_AVAILABLE)
            except ValueError:
                return str(DataMarker.NOT_AVAILABLE)
