"""Smoke tests for netcheck.network.interfaces.

Interface type detection populates ``InterfaceInfo.device`` with a
``DeviceInfo`` dataclass (carrying a ``DataStatus`` and an optional name)
rather than a bare ``str | None``.  This lets callers distinguish "hardware
not applicable to this interface type" (``NOT_APPLICABLE``), "lookup failed"
(``ERROR``), and "no data returned" (``UNAVAILABLE``) without inspecting
sentinel strings.
"""

from netcheck.core.enums import DataStatus, InterfaceType
from netcheck.core.models import DeviceInfo
from netcheck.network.interfaces import (
    _is_bridge,
    _is_ethernet,
    _is_tuntap,
    _is_veth,
    _is_vpn_by_name,
    _is_wireguard,
    detect_interface_type,
    get_device_name,
    get_interface_list,
)
from tests.fakes import FakeCommandRunner, FakeSysfsReader

_USB_PATH = "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0"
_PCI_PATH = "/sys/devices/pci0000:00/0000:00:1f.6"


class TestGetInterfaceList:
    """get_interface_list parses ip -o link show output."""

    def test_names_extracted(self) -> None:
        runner = FakeCommandRunner(
            {("ip", "-o", "link", "show"):
             "1: lo: <LOOPBACK,UP> mtu 65536\n2: eth0: <BROADCAST,UP> mtu 1500"}
        )
        names = get_interface_list(runner)
        assert "lo" in names
        assert "eth0" in names

    def test_command_failure_returns_empty(self) -> None:
        runner = FakeCommandRunner({("ip", "-o", "link", "show"): None})
        assert not get_interface_list(runner)

    def test_veth_at_sign_stripped(self) -> None:
        runner = FakeCommandRunner(
            {("ip", "-o", "link", "show"): "5: veth0@if2: <BROADCAST> mtu 1500"}
        )
        assert "veth0" in get_interface_list(runner)


class TestDetectInterfaceType:
    """detect_interface_type covers the main priority chain branches."""

    def _run(
        self,
        iface: str,
        modem_ifaces: frozenset[str] = frozenset(),
    ) -> InterfaceType:
        reader = FakeSysfsReader()
        return detect_interface_type(iface, modem_ifaces, reader)

    def test_lo_is_loopback(self) -> None:
        assert self._run("lo") == InterfaceType.LOOPBACK

    def test_tun_is_vpn(self) -> None:
        assert self._run("tun0") == InterfaceType.VPN

    def test_eth_is_ethernet(self) -> None:
        # Uses the sysfs ARPHRD type=1 check (priority 10).
        reader = FakeSysfsReader(files={("/sys/class/net/eth0", "type"): "1"})
        result = detect_interface_type("eth0", frozenset(), reader)
        assert result == InterfaceType.ETHERNET

    def test_modem_iface_is_cellular(self) -> None:
        result = self._run("wwp195s0f3u4", modem_ifaces=frozenset({"wwp195s0f3u4"}))
        assert result == InterfaceType.CELLULAR

    def test_unknown_name_is_unknown(self) -> None:
        assert self._run("xyz99") == InterfaceType.UNKNOWN


class TestGetDeviceName:
    """get_device_name must return DeviceInfo (not str | None)."""

    def _run(
        self,
        iface: str,
        iface_type: InterfaceType,
        device_path: str | None = None,
        files: dict[tuple[str, str], str] | None = None,
        *,
        runner_responses: dict[tuple[str, ...], str | None] | None = None,
    ) -> DeviceInfo:
        reader = FakeSysfsReader(
            device_paths={iface: device_path} if device_path else {},
            files=files or {},
        )
        runner = FakeCommandRunner(runner_responses or {})
        return get_device_name(iface, iface_type, reader, runner)

    def test_returns_device_info(self) -> None:
        """Return value must be a DeviceInfo instance."""
        result = self._run("lo", InterfaceType.LOOPBACK)
        assert isinstance(result, DeviceInfo)

    def test_loopback_is_not_applicable(self) -> None:
        result = self._run("lo", InterfaceType.LOOPBACK)
        assert result.status == DataStatus.NOT_APPLICABLE
        assert result.name is None

    def test_vpn_is_not_applicable(self) -> None:
        result = self._run("tun0", InterfaceType.VPN)
        assert result.status == DataStatus.NOT_APPLICABLE

    def test_ethernet_no_sysfs_is_unavailable(self) -> None:
        """Ethernet without any sysfs device path must be UNAVAILABLE."""
        result = self._run("eth0", InterfaceType.ETHERNET)
        assert result.status == DataStatus.UNAVAILABLE
        assert result.name is None

    def test_pci_device_returns_ok(self) -> None:
        """A PCI device with valid lspci output must return OK with name."""
        lspci_output = (
            "00:1f.6 Ethernet controller: Intel Corporation I219-V (rev 03)"
        )
        result = self._run(
            "eth0",
            InterfaceType.ETHERNET,
            device_path=_PCI_PATH,
            files={
                (_PCI_PATH, "vendor"): "8086",
                (_PCI_PATH, "device"): "15bc",
            },
            runner_responses={("lspci", "-d", "8086:15bc"): lspci_output},
        )
        assert result.status == DataStatus.OK
        assert result.name is not None
        assert "Intel" in result.name

    def test_pci_lspci_failure_returns_error(self) -> None:
        """sysfs IDs found but lspci fails: status must be ERROR."""
        result = self._run(
            "eth0",
            InterfaceType.ETHERNET,
            device_path=_PCI_PATH,
            files={
                (_PCI_PATH, "vendor"): "8086",
                (_PCI_PATH, "device"): "15bc",
            },
            runner_responses={("lspci", "-d", "8086:15bc"): None},
        )
        assert result.status == DataStatus.ERROR
        assert result.name is None


class TestGetDeviceNameUsb:
    """get_device_name: USB code paths."""

    _USB_PATH = "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0"

    def test_usb_ok(self) -> None:
        """USB interface with valid lsusb output -> OK with name."""
        vendor_path = "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2"
        reader = FakeSysfsReader(
            device_paths={"enx0": self._USB_PATH},
            files={
                # idVendor/idProduct are on the parent USB device, not the
                # interface path.  Keys absent from the dict return None,
                # which is the correct signal for "not at this level".
                (vendor_path, "idVendor"): "18d1",
                (vendor_path, "idProduct"): "4eeb",
            },
        )
        runner = FakeCommandRunner(
            {("lsusb", "-d", "18d1:4eeb"): "Bus 001 Device 003: ID 18d1:4eeb Google LLC Pixel 9a"}
        )
        result = get_device_name("enx0", InterfaceType.TETHER, reader, runner)
        assert result.status == DataStatus.OK
        assert result.name is not None
        assert "Google" in result.name or "Pixel" in result.name

    def test_usb_no_sysfs_ids_returns_unavailable(self) -> None:
        """USB interface with no idVendor/idProduct in sysfs -> UNAVAILABLE.

        find_usb_ids walks the sysfs tree and returns None when the ID files
        are absent.  The interface is USB-backed but no hardware identity
        could be retrieved; this is UNAVAILABLE, not ERROR.
        """
        reader = FakeSysfsReader(
            device_paths={"enx0": self._USB_PATH},
            # No idVendor / idProduct files anywhere in the tree.
        )
        runner = FakeCommandRunner({})
        result = get_device_name("enx0", InterfaceType.TETHER, reader, runner)
        assert result.status == DataStatus.UNAVAILABLE
        assert result.name is None

    def test_usb_lsusb_failure_returns_error(self) -> None:
        """USB IDs found but lsusb fails -> ERROR."""
        vendor_path = "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2"
        reader = FakeSysfsReader(
            device_paths={"enx0": self._USB_PATH},
            files={
                (vendor_path, "idVendor"): "18d1",
                (vendor_path, "idProduct"): "4eeb",
            },
        )
        runner = FakeCommandRunner({("lsusb", "-d", "18d1:4eeb"): None})
        result = get_device_name("enx0", InterfaceType.TETHER, reader, runner)
        assert result.status == DataStatus.ERROR

    def test_usb_whitespace_name_returns_error(self) -> None:
        """lsusb output that matches the pattern but yields an empty name -> ERROR.

        ``lookup_usb_name`` returns ``None`` when ``match.group(1).strip()``
        evaluates to an empty string (the ``or None`` branch).  This is
        distinct from a hard lsusb failure (runner returns ``None`` outright):
        the command succeeded and the output was parseable, but the captured
        device name contained only whitespace.

        ``get_device_name`` treats any ``None`` from ``lookup_usb_name`` the
        same way it treats a command failure: ``DeviceInfo.error()``.
        """
        vendor_path = "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2"
        reader = FakeSysfsReader(
            device_paths={"enx0": self._USB_PATH},
            files={
                (vendor_path, "idVendor"): "18d1",
                (vendor_path, "idProduct"): "4eeb",
            },
        )
        # Two trailing spaces: \s+ in the regex eats one, (.+) captures the
        # other, .strip() -> "", "" or None -> None.
        runner = FakeCommandRunner(
            {("lsusb", "-d", "18d1:4eeb"): "Bus 001 Device 001: ID 18d1:4eeb  "}
        )
        result = get_device_name("enx0", InterfaceType.TETHER, reader, runner)
        assert result.status == DataStatus.ERROR
        assert result.name is None

    def test_bridge_type_not_applicable(self) -> None:
        result = get_device_name(
            "br0", InterfaceType.BRIDGE, FakeSysfsReader(), FakeCommandRunner({})
        )
        assert result.status == DataStatus.NOT_APPLICABLE

    def test_virtual_type_not_applicable(self) -> None:
        result = get_device_name(
            "veth0", InterfaceType.VIRTUAL, FakeSysfsReader(), FakeCommandRunner({})
        )
        assert result.status == DataStatus.NOT_APPLICABLE


class TestIsVpnByNameExtended:
    """_is_vpn_by_name: additional prefix coverage."""

    def test_ppp_is_vpn(self) -> None:
        assert _is_vpn_by_name("ppp0") is True

    def test_tap_is_vpn(self) -> None:
        assert _is_vpn_by_name("tap0") is True

    def test_wg_prefix_is_vpn(self) -> None:
        assert _is_vpn_by_name("wg0") is True

    def test_pvpn_substring_is_vpn(self) -> None:
        assert _is_vpn_by_name("pvpnksintrf0") is True

    def test_br_is_not_vpn(self) -> None:
        assert _is_vpn_by_name("br0") is False


class TestIsEthernet:
    """_is_ethernet: ARPHRD_ETHER sysfs type check (priority 9)."""

    def test_type_1_returns_true(self) -> None:
        """sysfs type file containing '1' must return True."""
        reader = FakeSysfsReader(files={("/sys/class/net/enp3s0", "type"): "1"})
        assert _is_ethernet("enp3s0", reader) is True

    def test_type_1_with_newline_returns_true(self) -> None:
        """Trailing newline (as the kernel writes) must be stripped before comparison."""
        reader = FakeSysfsReader(files={("/sys/class/net/enp3s0", "type"): "1\n"})
        assert _is_ethernet("enp3s0", reader) is True

    def test_type_772_returns_false(self) -> None:
        """ARPHRD_LOOPBACK (772) must not be classified as Ethernet."""
        reader = FakeSysfsReader(files={("/sys/class/net/lo", "type"): "772"})
        assert _is_ethernet("lo", reader) is False

    def test_absent_type_file_returns_false(self) -> None:
        """Missing type file must return False without raising."""
        reader = FakeSysfsReader()
        assert _is_ethernet("eth0", reader) is False

    def test_generic_name_with_type_1_is_ethernet(self) -> None:
        """Any interface name with sysfs type=1 must be Ethernet."""
        reader = FakeSysfsReader(files={("/sys/class/net/net5", "type"): "1"})
        result = detect_interface_type("net5", frozenset(), reader)
        assert result == InterfaceType.ETHERNET

    def test_type_1_without_sysfs_file_is_unknown(self) -> None:
        """Interface with no sysfs type file and no matching name prefix must be UNKNOWN.

        Documents the failure mode on hardware or configurations where the sysfs
        type file is unexpectedly absent.  On the target platform (kernel 6.x)
        this should never occur in practice.
        """
        reader = FakeSysfsReader()
        result = detect_interface_type("enp3s0", frozenset(), reader)
        assert result == InterfaceType.UNKNOWN

    def test_arphrd_fires_after_vpn_name(self) -> None:
        """A VPN-named interface must be VPN even if sysfs type=1 (priority 5 > 9)."""
        reader = FakeSysfsReader(files={("/sys/class/net/tun0", "type"): "1"})
        result = detect_interface_type("tun0", frozenset(), reader)
        assert result == InterfaceType.VPN

    def test_arphrd_fires_after_wireless(self) -> None:
        """A wireless interface (phy80211 present) must be WIRELESS even if
        type=1 (priority 6 > 9)."""
        reader = FakeSysfsReader(
            link_names={("/sys/class/net/wlan0", "phy80211"): "phy0"},
            files={("/sys/class/net/wlan0", "type"): "1"},
        )
        result = detect_interface_type("wlan0", frozenset(), reader)
        assert result == InterfaceType.WIRELESS


class TestIsBridge:
    """_is_bridge: sysfs bridge/ directory detection."""

    def test_bridge_dir_present_returns_true(self) -> None:
        """Interface with bridge/ dir in sysfs must return True."""
        reader = FakeSysfsReader(
            dirs=frozenset({"/sys/class/net/br0/bridge"})
        )
        assert _is_bridge("br0", reader) is True

    def test_bridge_dir_absent_returns_false(self) -> None:
        """Interface without bridge/ dir must return False."""
        reader = FakeSysfsReader()
        assert _is_bridge("eth0", reader) is False

    def test_checks_correct_sysfs_path(self) -> None:
        """_is_bridge must check /sys/class/net/<iface>/bridge for the given name."""
        reader = FakeSysfsReader(
            dirs=frozenset({"/sys/class/net/docker0/bridge"})
        )
        assert _is_bridge("docker0", reader) is True
        assert _is_bridge("br0", reader) is False


class TestDetectInterfaceTypeBridge:
    """detect_interface_type: bridge sysfs detection (priority 7)."""

    def test_bridge_dir_present_is_bridge(self) -> None:
        """Interface with bridge/ dir in sysfs must be classified as BRIDGE."""
        reader = FakeSysfsReader(
            dirs=frozenset({"/sys/class/net/br0/bridge"})
        )
        result = detect_interface_type("br0", frozenset(), reader)
        assert result == InterfaceType.BRIDGE

    def test_bridge_dir_absent_passes_through(self) -> None:
        """Interface without bridge/ dir and no other signal must not be BRIDGE.

        With bridge/ absent and no sysfs type file, a plain br0 name falls
        through to UNKNOWN.
        """
        reader = FakeSysfsReader()
        result = detect_interface_type("br0", frozenset(), reader)
        assert result != InterfaceType.BRIDGE

    def test_wireless_takes_priority_over_bridge(self) -> None:
        """WIRELESS (priority 6) must fire before BRIDGE (priority 7) when
        both phy80211 symlink and bridge/ dir are present."""
        reader = FakeSysfsReader(
            link_names={("/sys/class/net/wbr0", "phy80211"): "phy0"},
            dirs=frozenset({"/sys/class/net/wbr0/bridge"}),
        )
        result = detect_interface_type("wbr0", frozenset(), reader)
        assert result == InterfaceType.WIRELESS

    def test_docker_bridge_dir_is_bridge(self) -> None:
        """docker0 with bridge/ dir must be BRIDGE without relying on the name prefix."""
        reader = FakeSysfsReader(
            dirs=frozenset({"/sys/class/net/docker0/bridge"})
        )
        result = detect_interface_type("docker0", frozenset(), reader)
        assert result == InterfaceType.BRIDGE


class TestIsVeth:
    """_is_veth: sysfs iflink/ifindex detection."""

    def test_differing_iflink_ifindex_returns_true(self) -> None:
        """iflink != ifindex must return True (veth pair)."""
        reader = FakeSysfsReader(
            files={
                ("/sys/class/net/veth0", "ifindex"): "5",
                ("/sys/class/net/veth0", "iflink"): "6",
            }
        )
        assert _is_veth("veth0", reader) is True

    def test_equal_iflink_ifindex_returns_false(self) -> None:
        """iflink == ifindex must return False (not a veth pair)."""
        reader = FakeSysfsReader(
            files={
                ("/sys/class/net/eth0", "ifindex"): "2",
                ("/sys/class/net/eth0", "iflink"): "2",
            }
        )
        assert _is_veth("eth0", reader) is False

    def test_missing_ifindex_returns_false(self) -> None:
        """Absent ifindex file must return False without raising."""
        reader = FakeSysfsReader(
            files={("/sys/class/net/veth0", "iflink"): "6"}
        )
        assert _is_veth("veth0", reader) is False

    def test_missing_iflink_returns_false(self) -> None:
        """Absent iflink file must return False without raising."""
        reader = FakeSysfsReader(
            files={("/sys/class/net/veth0", "ifindex"): "5"}
        )
        assert _is_veth("veth0", reader) is False

    def test_non_integer_content_returns_false(self) -> None:
        """Non-integer file content must return False without raising."""
        reader = FakeSysfsReader(
            files={
                ("/sys/class/net/veth0", "ifindex"): "five",
                ("/sys/class/net/veth0", "iflink"): "six",
            }
        )
        assert _is_veth("veth0", reader) is False


class TestDetectInterfaceTypeVeth:
    """detect_interface_type: veth sysfs detection (priority 8)."""

    def test_differing_iflink_ifindex_is_virtual(self) -> None:
        """Interface with iflink != ifindex must be classified as VIRTUAL."""
        reader = FakeSysfsReader(
            files={
                ("/sys/class/net/veth0", "ifindex"): "5",
                ("/sys/class/net/veth0", "iflink"): "6",
            }
        )
        result = detect_interface_type("veth0", frozenset(), reader)
        assert result == InterfaceType.VIRTUAL

    def test_equal_iflink_ifindex_passes_through(self) -> None:
        """Interface with iflink == ifindex and no other signal must not be VIRTUAL."""
        reader = FakeSysfsReader(
            files={
                ("/sys/class/net/xyz0", "ifindex"): "3",
                ("/sys/class/net/xyz0", "iflink"): "3",
            }
        )
        result = detect_interface_type("xyz0", frozenset(), reader)
        assert result != InterfaceType.VIRTUAL

    def test_bridge_takes_priority_over_veth(self) -> None:
        """BRIDGE (priority 7) must fire before VIRTUAL (priority 8) when
        both bridge/ dir and differing iflink/ifindex are present."""
        reader = FakeSysfsReader(
            dirs=frozenset({"/sys/class/net/br0/bridge"}),
            files={
                ("/sys/class/net/br0", "ifindex"): "3",
                ("/sys/class/net/br0", "iflink"): "4",
            },
        )
        result = detect_interface_type("br0", frozenset(), reader)
        assert result == InterfaceType.BRIDGE

    def test_veth_prefix_name_no_sysfs_is_unknown(self) -> None:
        """A veth-prefixed interface with no sysfs data must fall through to UNKNOWN.

        Without an iflink/ifindex mismatch, the name prefix alone does not
        determine the type; the interface correctly falls through to UNKNOWN.
        """
        reader = FakeSysfsReader()
        result = detect_interface_type("veth0", frozenset(), reader)
        assert result == InterfaceType.UNKNOWN


class TestIsWireguard:
    """_is_wireguard: sysfs type=65534 + no tun_flags detection."""

    def test_type_65534_no_tun_flags_returns_true(self) -> None:
        """type=65534 with no tun_flags must return True (WireGuard)."""
        reader = FakeSysfsReader(
            files={("/sys/class/net/wg0", "type"): "65534"}
        )
        assert _is_wireguard("wg0", reader) is True

    def test_type_65534_with_tun_flags_returns_false(self) -> None:
        """type=65534 with tun_flags present must return False (TUN, not WireGuard)."""
        reader = FakeSysfsReader(
            files={
                ("/sys/class/net/tun0", "type"): "65534",
                ("/sys/class/net/tun0", "tun_flags"): "0x0001",
            }
        )
        assert _is_wireguard("tun0", reader) is False

    def test_type_1_no_tun_flags_returns_false(self) -> None:
        """type=1 (ARPHRD_ETHER) must not be WireGuard."""
        reader = FakeSysfsReader(
            files={("/sys/class/net/eth0", "type"): "1"}
        )
        assert _is_wireguard("eth0", reader) is False

    def test_absent_type_file_returns_false(self) -> None:
        """Missing type file must return False without raising."""
        reader = FakeSysfsReader()
        assert _is_wireguard("wg0", reader) is False

    def test_namespace_isolated_wireguard_returns_true(self) -> None:
        """Namespace-isolated WireGuard (no abi_version, type=65534) must return True.

        ProtonVPN's proton0 interface is WireGuard in a private namespace.
        abi_version is absent; the type file is the only reliable signal.
        """
        reader = FakeSysfsReader(
            files={("/sys/class/net/proton0", "type"): "65534"}
            # abi_version intentionally absent
        )
        assert _is_wireguard("proton0", reader) is True


class TestIsTuntap:
    """_is_tuntap: sysfs tun_flags detection."""

    def test_tun_flags_present_returns_true(self) -> None:
        """tun_flags file present must return True."""
        reader = FakeSysfsReader(
            files={("/sys/class/net/tun0", "tun_flags"): "0x0001"}
        )
        assert _is_tuntap("tun0", reader) is True

    def test_tun_flags_absent_returns_false(self) -> None:
        """Missing tun_flags file must return False."""
        reader = FakeSysfsReader()
        assert _is_tuntap("tun0", reader) is False


class TestDetectInterfaceTypeTether:
    """detect_interface_type: USB tether detection (priority 4)."""

    def test_usb_tether_driver_is_tether(self) -> None:
        """Interface backed by a tether USB driver must be TETHER."""
        usb_path = "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0"
        reader = FakeSysfsReader(
            device_paths={"enx001234567890": usb_path},
            link_names={(usb_path, "driver"): "cdc_ether"},
        )
        result = detect_interface_type("enx001234567890", frozenset(), reader)
        assert result == InterfaceType.TETHER

    def test_non_tether_usb_driver_not_tether(self) -> None:
        """USB interface with an unrecognised driver must not be TETHER."""
        usb_path = "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-3/1-3:1.0"
        reader = FakeSysfsReader(
            device_paths={"usb0": usb_path},
            link_names={(usb_path, "driver"): "usbnet"},
        )
        result = detect_interface_type("usb0", frozenset(), reader)
        assert result != InterfaceType.TETHER
