"""USB hardware device detection and name lookup for netcheck.

Determines whether a network interface is backed by a USB device, identifies
its driver (for tether vs modem classification), and resolves a human-readable
name via ``lsusb``.  Returns raw names; display-layer formatting lives in
``netcheck/output/formatters.py``.

sysfs layout
------------
For a USB network interface such as ``enx8615d34feca4``, sysfs exposes::

    /sys/class/net/enx8615d34feca4/device  -> symlink into USB device tree

The resolved path contains ``/usb`` for USB devices.  The driver is read from
the ``driver`` symlink under the device path.  Vendor/product IDs live one or
more levels up the tree (the network interface points to the USB *interface*,
not the USB *device* which holds the IDs).

lsusb output format
-------------------
``lsusb -d <vendor>:<product>`` returns one line::

    Bus 001 Device 003: ID 18d1:4eeb Google LLC Pixel 9a

The device name is everything after ``ID xxxx:xxxx``.

Injection
---------
All sysfs operations receive a ``SysfsReader`` rather than accessing
``pathlib.Path`` directly.  This makes every function in this module fully
testable without a real USB device or sysfs, using ``FakeSysfsReader`` from
``tests/fakes.py``.

``find_usb_ids`` walks up the sysfs tree using the reader's ``parent_path``
operation, keeping the walk logic pure and testable without filesystem access.
"""

import re
from typing import Final

from netcheck.utils.command import CommandRunner
from netcheck.utils.sysfs import SysfsReader

# Matches the device name after the USB ID in lsusb output.
_LSUSB_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"ID\s+[0-9a-f]{4}:[0-9a-f]{4}\s+(.+)$",
    re.IGNORECASE,
)

# USB tether drivers -- interfaces using these are phone-tethered devices.
# Cellular modems use these drivers too, but are identified first via
# ModemManager before this module is consulted.
USB_TETHER_DRIVERS: Final[frozenset[str]] = frozenset(
    {
        "cdc_ether",
        "cdc_mbim",
        "cdc_ncm",
        "ipheth",
        "rndis_host",
    }
)

# USB net interface -> USB interface -> USB config -> USB device: 3 levels.
# Allow 5 to accommodate an extra level of hub nesting without unbounded walking.
_MAX_SYSFS_WALK_DEPTH: Final[int] = 5


def is_usb_interface(iface_name: str, reader: SysfsReader) -> bool:
    """Return ``True`` if ``iface_name`` is backed by a USB device.

    Checks whether the resolved sysfs device path contains ``/usb``.

    Args:
        iface_name: Network interface name.
        reader: Sysfs reader used to resolve the device path.

    Returns:
        ``True`` if USB, ``False`` otherwise.
    """
    device_path = reader.device_path(iface_name)
    if device_path is None:
        return False
    return "/usb" in device_path


def get_usb_driver(iface_name: str, reader: SysfsReader) -> str | None:
    """Return the kernel driver name for a USB interface, or ``None``.

    Reads the ``driver`` symlink from the sysfs device path.

    Args:
        iface_name: Network interface name.
        reader: Sysfs reader used to resolve the device path and driver link.

    Returns:
        Driver name (e.g. ``"cdc_ether"``, ``"rndis_host"``), or ``None``
        if the interface is not USB or the driver cannot be determined.
    """
    device_path = reader.device_path(iface_name)
    if device_path is None or "/usb" not in device_path:
        return None
    return reader.read_link_name(device_path, "driver")


def is_usb_tether(iface_name: str, reader: SysfsReader) -> bool:
    """Return ``True`` if ``iface_name`` uses a USB tether driver.

    This check runs *after* ModemManager detection in the interface type
    detection chain.  If ModemManager claims the interface, it is classified
    as ``CELLULAR`` and this function is never reached for it.

    Args:
        iface_name: Network interface name.
        reader: Sysfs reader passed through to ``get_usb_driver``.

    Returns:
        ``True`` if the interface is USB and uses a known tether driver.
    """
    driver = get_usb_driver(iface_name, reader)
    if driver is None:
        return False
    return driver in USB_TETHER_DRIVERS


def get_usb_device_name(
    iface_name: str,
    reader: SysfsReader,
    runner: CommandRunner,
) -> str | None:
    """Return the raw USB device name for ``iface_name``, or ``None``.

    Walks up the sysfs tree via ``reader`` to find USB vendor/product IDs,
    then queries ``lsusb`` via ``runner`` for the human-readable name.

    Args:
        iface_name: Network interface name.
        reader: Sysfs reader for USB ID discovery.
        runner: Command runner for ``lsusb`` invocations.

    Returns:
        Raw device name string (e.g. ``"Google LLC Pixel 9a"``),
        or ``None`` if IDs cannot be found or ``lsusb`` fails.
    """
    device_path = reader.device_path(iface_name)
    if device_path is None or "/usb" not in device_path:
        return None

    ids = find_usb_ids(device_path, reader)
    if ids is None:
        return None

    vendor, product = ids
    return lookup_usb_name(vendor, product, runner)


def find_usb_ids(device_path: str, reader: SysfsReader) -> tuple[str, str] | None:
    """Walk up the sysfs tree to find USB vendor/product IDs.

    Network interfaces point to the USB *interface* in sysfs, but the
    ``idVendor``/``idProduct`` files are on the USB *device* node one or
    more levels above.  This function walks upward using ``reader.parent_path``
    until the ID files are found or the root is reached.

    Args:
        device_path: Starting sysfs path (the resolved interface device path).
        reader: Sysfs reader for file reads and upward tree traversal.

    Returns:
        ``(vendor, product)`` as four-character hex strings, or ``None`` if
        the IDs cannot be found within ``_MAX_SYSFS_WALK_DEPTH`` levels.
    """
    current = device_path
    for _ in range(_MAX_SYSFS_WALK_DEPTH):
        vendor = reader.read_file(current, "idVendor")
        product = reader.read_file(current, "idProduct")
        if vendor and product and len(vendor) == 4 and len(product) == 4:
            return (vendor, product)

        parent = reader.parent_path(current)
        if parent is None:
            break
        current = parent

    return None


def lookup_usb_name(
    vendor: str, product: str, runner: CommandRunner
) -> str | None:
    """Resolve USB IDs to a device name via ``lsusb``.

    Args:
        vendor: Vendor ID (e.g. ``"18d1"``).
        product: Product ID (e.g. ``"4eeb"``).
        runner: Command runner.

    Returns:
        Device name extracted from ``lsusb`` output, or ``None`` on failure.
    """
    output = runner.run(["lsusb", "-d", f"{vendor}:{product}"])
    if not output:
        return None

    match = _LSUSB_NAME_PATTERN.search(output)
    if not match:
        return None

    return match.group(1).strip() or None
