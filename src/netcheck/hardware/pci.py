"""PCI hardware device name lookup for netcheck.

Reads vendor and device IDs from sysfs and resolves them to human-readable
names via ``lspci``.  Returns raw names; display-layer formatting lives in
``netcheck/output/formatters.py``.

sysfs layout
------------
For a PCI network interface ``eth0``, the IDs are at::

    /sys/class/net/eth0/device/vendor   -> "0x8086"
    /sys/class/net/eth0/device/device   -> "0x15bc"

The device symlink is followed to the real sysfs path before reading.

lspci output format
-------------------
``lspci -d <vendor>:<device>`` returns one line per matching device::

    00:1f.6 Ethernet controller: Intel Corporation Ethernet Controller I219-V (rev 03)

The device name is everything after the last ``<Class>:`` field.

Injection
---------
Both ``read_pci_ids`` and ``get_pci_device_name`` receive a ``SysfsReader``
rather than accessing ``pathlib.Path`` directly.  This makes the module fully
testable without a real PCI device or sysfs, using ``FakeSysfsReader`` from
``tests/fakes.py``.
"""

import re
from typing import Final

from netcheck.utils.command import CommandRunner
from netcheck.utils.sysfs import SysfsReader

# Matches "Class label: Device name" in lspci output.
# The class label ends with a colon; everything after is the device name.
_LSPCI_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"[^:]+:\s+(.+)$")


def get_pci_device_name(
    iface_name: str,
    reader: SysfsReader,
    runner: CommandRunner,
) -> str | None:
    """Return the raw PCI device name for ``iface_name``, or ``None``.

    Reads vendor/device IDs from sysfs via ``reader``, then delegates to
    ``lspci`` via ``runner`` for the human-readable name.  Returns ``None``
    at any point where data is missing or a command fails -- the caller decides
    what default to use.

    Args:
        iface_name: Network interface name (e.g. ``"eth0"``).
        reader: Sysfs reader for vendor/device ID files.
        runner: Command runner for ``lspci`` invocations.

    Returns:
        Raw device name string (e.g.
        ``"Intel Corporation Ethernet Controller I219-V (rev 03)"``),
        or ``None`` if IDs cannot be read or ``lspci`` fails.
    """
    ids = read_pci_ids(iface_name, reader)
    if ids is None:
        return None

    vendor, device = ids
    return lookup_pci_name(vendor, device, runner)


def read_pci_ids(iface_name: str, reader: SysfsReader) -> tuple[str, str] | None:
    """Read PCI vendor and device IDs from sysfs via ``reader``.

    Args:
        iface_name: Interface name.
        reader: Sysfs reader used to resolve the device path and read files.

    Returns:
        ``(vendor, device)`` hex strings without the ``0x`` prefix,
        or ``None`` if the interface has no PCI device or the files
        cannot be read.
    """
    device_path = reader.device_path(iface_name)
    if device_path is None:
        return None

    vendor_raw = reader.read_file(device_path, "vendor")
    device_raw = reader.read_file(device_path, "device")

    if not vendor_raw or not device_raw:
        return None

    vendor = vendor_raw.removeprefix("0x")
    device = device_raw.removeprefix("0x")

    if not vendor or not device:
        return None

    return (vendor, device)


def lookup_pci_name(vendor: str, device: str, runner: CommandRunner) -> str | None:
    """Resolve PCI IDs to a device name via ``lspci``.

    Args:
        vendor: Vendor ID hex string (e.g. ``"8086"``).
        device: Device ID hex string (e.g. ``"15bc"``).
        runner: Command runner.

    Returns:
        Device name extracted from ``lspci`` output, or ``None`` on failure.
    """
    output = runner.run(["lspci", "-d", f"{vendor}:{device}"])
    if not output:
        return None

    # Use only the first line in case multiple devices match
    first_line = output.splitlines()[0]
    match = _LSPCI_NAME_PATTERN.search(first_line)
    if not match:
        return None

    return match.group(1).strip() or None
