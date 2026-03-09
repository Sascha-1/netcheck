"""Interface discovery, classification, and hardware name resolution.

Provides:
- ``get_interface_list``   -- all interface names from ``ip -o link show``.
- ``detect_interface_type``-- classify one interface into ``InterfaceType``.
- ``get_device_name``      -- hardware description as ``DeviceInfo``.

Detection priority for ``detect_interface_type``
------------------------------------------------
1. ``LOOPBACK``  -- name is exactly ``"lo"``.
2. ``CELLULAR``  -- name is in ``modem_interfaces`` (from ModemManager).
3. ``CELLULAR``  -- name starts with ``"ww"`` (WWAN predictable naming prefix).
                   This is a fallback for when ModemManager is unavailable
                   (e.g. no SIM card inserted and the modem is in a failed
                   state not reported by ``mmcli``).  The ``ww`` prefix is
                   assigned by ``systemd-udevd`` to all WWAN interfaces under
                   predictable network interface naming, in the same way that
                   ``wl`` is used for wireless and ``en``/``eth`` for Ethernet.
4. ``TETHER``    -- USB device with a tethering kernel driver.
5. ``VPN``       -- name starts with a VPN prefix (``_is_vpn_by_name``).
6. ``WIRELESS``  -- sysfs ``phy80211`` symlink is present.
7. ``BRIDGE``    -- sysfs ``/sys/class/net/<iface>/bridge/`` directory is
                   present.  The kernel creates this directory exclusively for
                   bridge master interfaces.  Authoritative sysfs signal;
                   consistent with wireless (step 6) and Ethernet (step 10).
8. ``VIRTUAL``   -- sysfs ``iflink != ifindex`` (``_is_veth``).  For veth
                   pairs the kernel writes a different integer to
                   ``/sys/class/net/<iface>/iflink`` (peer index) than to
                   ``/sys/class/net/<iface>/ifindex`` (own index).  For all
                   other interface types reaching this step the two values are
                   equal.
9. ``VPN``       -- sysfs fallback for VPN interfaces not caught by the name
                   check at step 5.  Two signals, checked in order:

                   a. ``tun_flags`` present (``_is_tuntap``) -> TUN or TAP.
                      The kernel's tun driver writes this file exclusively for
                      TUN and TAP interfaces.

                   b. ``type == "65534"`` (``ARPHRD_NONE``) and ``tun_flags``
                      absent (``_is_wireguard``) -> WireGuard.  All WireGuard
                      interfaces use ``ARPHRD_NONE`` regardless of network
                      namespace isolation; ``abi_version`` is NOT used because
                      it is absent for namespace-isolated interfaces.

10. ``ETHERNET`` -- sysfs ``/sys/class/net/<iface>/type`` equals ``1``
                   (``ARPHRD_ETHER``).  Authoritative, kernel-assigned ARP
                   hardware type; does not depend on interface naming
                   conventions.  Consistent with how wireless is detected
                   via the ``phy80211`` symlink at step 6.
11. ``UNKNOWN``  -- no rule matched.

Rationale for step 3 (``ww`` prefix before tether check)
---------------------------------------------------------
Cellular modems and tethered phones share kernel drivers (e.g. ``cdc_mbim``,
``cdc_ncm``).  The ModemManager check at step 2 is the authoritative way to
distinguish them, but ModemManager does not report modems that are in a failed
state (e.g. no SIM inserted).  Without the ``ww`` prefix check at step 3,
a cellular modem interface like ``wwp195s0f3u4`` would reach step 4 and be
classified as ``TETHER`` -- incorrect.  The ``ww`` prefix is unambiguously
assigned to WWAN interfaces by the kernel's predictable naming rules; it is
never used for tethered phones.

``get_device_name`` return value
---------------------------------
Returns a ``DeviceInfo`` that distinguishes:

- ``DataStatus.NOT_APPLICABLE`` -- no hardware exists for this interface type
  (loopback, VPN, virtual, bridge).  No lookup was attempted.
- ``DataStatus.UNAVAILABLE``    -- the interface could have hardware, but sysfs
  contains no PCI or USB device data.
- ``DataStatus.ERROR``          -- sysfs IDs were found but the lookup tool
  (lspci or lsusb) failed.
- ``DataStatus.OK``             -- ``name`` is populated with the raw hardware
  description string.

``modem_interfaces`` is pre-fetched by the orchestrator (one ModemManager
query per run) and passed in here.  This avoids repeated ``mmcli`` calls
and keeps the function testable with ``FakeSysfsReader`` and
``FakeCommandRunner`` alone.
"""

import re
from typing import Final

from netcheck.config import VPN_NAME_PREFIXES
from netcheck.core.enums import InterfaceType
from netcheck.core.models import DeviceInfo
from netcheck.hardware.pci import get_pci_device_name, read_pci_ids
from netcheck.hardware.usb import (
    find_usb_ids,
    is_usb_interface,
    is_usb_tether,
    lookup_usb_name,
)
from netcheck.utils.command import CommandRunner
from netcheck.utils.sysfs import SysfsReader
from netcheck.utils.validators import parse_interface_name

# ARP hardware type for standard Ethernet (ARPHRD_ETHER in <net/if_arp.h>).
# The kernel writes this integer as a decimal string to
# /sys/class/net/<iface>/type for every physical Ethernet interface,
# regardless of its name.  Stable sysfs ABI since kernel 2.6; always
# present on kernel 6.x.
_ARPHRD_ETHERNET: Final[str] = "1"

# ARP hardware type shared by WireGuard and TUN/TAP (ARPHRD_NONE in
# <net/if_arp.h>).  WireGuard uses it because it has no ARP framing;
# TUN/TAP uses it for the same reason.  The tun_flags file distinguishes
# TUN/TAP from WireGuard when both have this type.  Present since kernel 2.6.
_ARPHRD_NONE: Final[str] = "65534"

# Interface types that have no associated hardware.
_NO_HARDWARE_TYPES: Final[frozenset[InterfaceType]] = frozenset(
    {InterfaceType.LOOPBACK, InterfaceType.VPN, InterfaceType.VIRTUAL, InterfaceType.BRIDGE}
)


def get_interface_list(runner: CommandRunner) -> list[str]:
    """Return all valid network interface names on the system.

    Runs ``ip -o link show`` and parses the interface name from each line.
    Names are validated by ``parse_interface_name`` before being included.

    Args:
        runner: Command runner.

    Returns:
        List of validated interface name strings.  Empty if the command
        fails or no interfaces are found.
    """
    output = runner.run(["ip", "-o", "link", "show"])
    if not output:
        return []

    names: list[str] = []
    for line in output.splitlines():
        match = re.match(r"^\d+:\s+([^:@\s]+)", line)
        if match:
            name = parse_interface_name(match.group(1).strip())
            if name is not None:
                names.append(name)
    return names


def detect_interface_type(
    iface_name: str,
    modem_interfaces: frozenset[str],
    reader: SysfsReader,
) -> InterfaceType:
    # The return-statement count matches the number of priority steps in the
    # detection chain (11 steps, 10 explicit returns + 1 fallthrough to UNKNOWN).
    # Each step is a self-contained guard clause; collapsing them into a lookup
    # table or nested conditionals would obscure the priority ordering that is
    # the central design contract of this function.
    """Classify ``iface_name`` into an ``InterfaceType``.

    Applies the priority chain documented in the module docstring.
    Returns ``InterfaceType.UNKNOWN`` if no rule matches.

    Args:
        iface_name: Interface name to classify.
        modem_interfaces: Set of interface names managed by ModemManager,
                          pre-fetched once by the orchestrator.
        reader: Sysfs reader for all detection steps.

    Returns:
        Classified ``InterfaceType``.
    """
    # Priority 1: loopback
    if iface_name == "lo":
        return InterfaceType.LOOPBACK

    # Priority 2: ModemManager-reported cellular modem
    if iface_name in modem_interfaces:
        return InterfaceType.CELLULAR

    # Priority 3: WWAN predictable name prefix (fallback when ModemManager
    # is unavailable, e.g. modem in failed state with no SIM inserted).
    # The "ww" prefix is assigned exclusively to WWAN interfaces by
    # systemd-udevd's predictable naming scheme.
    if iface_name.startswith("ww"):
        return InterfaceType.CELLULAR

    # Priority 4: USB tethered device (phone, tablet)
    if is_usb_tether(iface_name, reader):
        return InterfaceType.TETHER

    # Priority 5: VPN by name
    if _is_vpn_by_name(iface_name):
        return InterfaceType.VPN

    # Priority 6: wireless (sysfs phy80211 symlink)
    if _is_wireless(iface_name, reader):
        return InterfaceType.WIRELESS

    # Priority 7: BRIDGE -- sysfs bridge/ directory present.
    # The kernel creates /sys/class/net/<iface>/bridge/ exclusively for bridge
    # master interfaces.  Its presence is the authoritative, always-current
    # kernel signal; consistent with how _is_wireless uses phy80211.
    if _is_bridge(iface_name, reader):
        return InterfaceType.BRIDGE

    # Priority 8: VIRTUAL -- sysfs iflink != ifindex.
    # For veth pairs the kernel writes a different value to iflink (peer index)
    # than to ifindex (own index).  For all other interface types reaching this
    # point the two values are equal.  Authoritative sysfs signal.
    if _is_veth(iface_name, reader):
        return InterfaceType.VIRTUAL

    # Priority 9: VPN sysfs fallback -- for VPN interfaces not caught by the
    # name check at step 5.  Checked before ARPHRD_ETHER because both
    # WireGuard and TUN/TAP use ARPHRD_NONE (type 65534), which would never
    # match the ARPHRD_ETHER check anyway; the ordering is a belt-and-
    # suspenders guard against future type-value collisions.
    #
    # TUN/TAP first: tun_flags is the most specific signal.
    if _is_tuntap(iface_name, reader):
        return InterfaceType.VPN
    # WireGuard: type == ARPHRD_NONE and no tun_flags.  Robust to namespace
    # isolation (abi_version is absent for proton0-style interfaces).
    if _is_wireguard(iface_name, reader):
        return InterfaceType.VPN

    # Priority 10: ARPHRD_ETHER sysfs type file -- authoritative kernel-level
    # Ethernet detection.  Reads /sys/class/net/<iface>/type and checks for
    # the value "1" (ARPHRD_ETHER).  Consistent with how wireless is detected
    # via the phy80211 symlink at priority 6: both use a sysfs kernel data
    # source rather than a naming convention.
    if _is_ethernet(iface_name, reader):
        return InterfaceType.ETHERNET

    # Priority 11: no rule matched.
    return InterfaceType.UNKNOWN


def get_device_name(
    iface_name: str,
    iface_type: InterfaceType,
    reader: SysfsReader,
    runner: CommandRunner,
) -> DeviceInfo:
    """Return the hardware description for ``iface_name`` as a ``DeviceInfo``.

    The returned ``DeviceInfo.status`` distinguishes why a name may be absent:

    - ``NOT_APPLICABLE`` -- interface type has no hardware (loopback, VPN,
                           virtual, bridge).  No lookup was attempted.
    - ``UNAVAILABLE``    -- no PCI or USB device data found in sysfs; the
                           interface exists but has no identifiable hardware.
    - ``ERROR``          -- sysfs IDs found but lspci or lsusb failed.
    - ``OK``             -- ``DeviceInfo.name`` is the raw hardware description.

    Args:
        iface_name: Interface name.
        iface_type: Pre-classified interface type.
        reader: Sysfs reader for hardware detection.
        runner: Command runner for lspci/lsusb queries.

    Returns:
        ``DeviceInfo`` with status and (for OK) the raw hardware description.
    """
    if iface_type in _NO_HARDWARE_TYPES:
        return DeviceInfo.not_applicable()

    if is_usb_interface(iface_name, reader):
        device_path = reader.device_path(iface_name)
        ids = find_usb_ids(device_path, reader) if device_path is not None else None
        if ids is None:
            return DeviceInfo.unavailable()
        name = lookup_usb_name(ids[0], ids[1], runner)
        return DeviceInfo.ok(name) if name is not None else DeviceInfo.error()

    if read_pci_ids(iface_name, reader) is not None:
        name = get_pci_device_name(iface_name, reader, runner)
        return DeviceInfo.ok(name) if name is not None else DeviceInfo.error()

    return DeviceInfo.unavailable()


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _is_vpn_by_name(iface_name: str) -> bool:
    """Return ``True`` if ``iface_name`` starts with a known VPN prefix.

    Args:
        iface_name: Interface name.

    Returns:
        ``True`` if the name matches a VPN prefix pattern.
    """
    lower = iface_name.lower()
    if "vpn" in lower:
        return True
    return any(lower.startswith(prefix) for prefix in VPN_NAME_PREFIXES)


def _is_wireless(iface_name: str, reader: SysfsReader) -> bool:
    """Return ``True`` if ``iface_name`` has a sysfs ``phy80211`` symlink.

    The ``phy80211`` directory/symlink is created by the kernel for every
    802.11 interface.  Its presence is the authoritative, sysfs-based test
    for wireless interfaces -- more reliable than name-prefix matching.

    Args:
        iface_name: Interface name.
        reader: Sysfs reader.

    Returns:
        ``True`` if wireless, ``False`` otherwise.
    """
    return reader.read_link_name(f"/sys/class/net/{iface_name}", "phy80211") is not None


def _is_bridge(iface_name: str, reader: SysfsReader) -> bool:
    """Return ``True`` if ``iface_name`` is a bridge master interface.

    The kernel creates ``/sys/class/net/<iface>/bridge/`` exclusively for
    bridge master interfaces.  Its presence is the authoritative sysfs
    signal, consistent with how ``_is_wireless`` uses ``phy80211`` and
    ``_is_ethernet`` uses the ``type`` file.

    Args:
        iface_name: Interface name.
        reader: Sysfs reader.

    Returns:
        ``True`` if the ``bridge/`` directory is present in sysfs,
        ``False`` otherwise.
    """
    return reader.dir_exists(f"/sys/class/net/{iface_name}/bridge")


def _is_veth(iface_name: str, reader: SysfsReader) -> bool:
    """Return ``True`` if ``iface_name`` is one end of a veth pair.

    The kernel writes ``ifindex`` (the interface's own index) and ``iflink``
    (the index of the peer interface) for every network interface.  For veth
    pairs these two values differ; for all other interface types that reach
    this point in the detection chain they are equal.

    Both files are read via the existing ``read_file`` primitive; no new
    sysfs primitive is required.

    Args:
        iface_name: Interface name.
        reader: Sysfs reader.

    Returns:
        ``True`` if ``iflink != ifindex`` (veth pair), ``False`` otherwise.
        Also returns ``False`` if either file is absent or contains a
        non-integer value.
    """
    base = f"/sys/class/net/{iface_name}"
    ifindex = reader.read_file(base, "ifindex")
    iflink = reader.read_file(base, "iflink")
    if ifindex is None or iflink is None:
        return False
    try:
        return int(ifindex) != int(iflink)
    except ValueError:
        return False


def _is_wireguard(iface_name: str, reader: SysfsReader) -> bool:
    """Return ``True`` if ``iface_name`` is a WireGuard interface.

    WireGuard interfaces use ``ARPHRD_NONE`` (type ``65534``) and do not
    expose ``tun_flags``.  This combination is robust to network namespace
    isolation: the ``type`` file is always present even when ``abi_version``
    is not (e.g. ProtonVPN's ``proton0`` interface).

    The check is ordered: ``tun_flags`` is tested first so that TUN/TAP
    interfaces (which also use ``ARPHRD_NONE``) are excluded before the
    type value is inspected.  This function is only called by the detection
    chain after ``_is_tuntap`` has already returned ``False``.

    Args:
        iface_name: Interface name.
        reader: Sysfs reader.

    Returns:
        ``True`` if ``type == "65534"`` and ``tun_flags`` is absent,
        ``False`` otherwise.
    """
    base = f"/sys/class/net/{iface_name}"
    if reader.read_file(base, "tun_flags") is not None:
        return False  # TUN or TAP, not WireGuard
    return reader.read_file(base, "type") == _ARPHRD_NONE


def _is_tuntap(iface_name: str, reader: SysfsReader) -> bool:
    """Return ``True`` if ``iface_name`` is a TUN or TAP interface.

    The kernel's tun driver writes ``tun_flags`` exclusively for TUN and TAP
    interfaces.  Its presence is the authoritative, always-current signal for
    this interface type -- more reliable than name-prefix matching and
    independent of network namespace.

    Args:
        iface_name: Interface name.
        reader: Sysfs reader.

    Returns:
        ``True`` if ``tun_flags`` is present in sysfs, ``False`` otherwise.
    """
    return reader.read_file(f"/sys/class/net/{iface_name}", "tun_flags") is not None


def _is_ethernet(iface_name: str, reader: SysfsReader) -> bool:
    """Return ``True`` if the kernel reports ``ARPHRD_ETHER`` for this interface.

    Reads ``/sys/class/net/<iface>/type`` and checks for the value ``"1"``,
    which is ``ARPHRD_ETHER`` as defined in ``<net/if_arp.h>``.  This is the
    authoritative, kernel-assigned ARP hardware type for standard Ethernet
    interfaces and is entirely independent of the interface name.

    This check is intentionally placed after all other specific-type checks
    (loopback, cellular, tether, VPN, wireless, bridge, virtual) so that
    no ambiguity can arise: by the time this function is called, every other
    interface type has already been excluded.

    The ``type`` file is stable sysfs ABI present since kernel 2.6 and is
    always populated on kernel 6.x for every interface.  It is never absent
    on the target platform (Debian 13 / Linux Mint 22.3 or newer).

    This approach is consistent with how wireless is detected via the
    ``phy80211`` symlink: both use a kernel-provided sysfs signal rather
    than a naming convention.

    Args:
        iface_name: Interface name.
        reader: Sysfs reader.

    Returns:
        ``True`` if the sysfs type file exists and contains ``"1"``
        (``ARPHRD_ETHER``), ``False`` otherwise (file absent or other type).
    """
    type_str = reader.read_file(f"/sys/class/net/{iface_name}", "type")
    return type_str is not None and type_str.strip() == _ARPHRD_ETHERNET
