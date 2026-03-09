"""Integration smoke tests for netcheck against the live system.

These tests make real system calls and require a Linux host with the ``ip``
command available.  They are excluded from the default ``make check`` run by
the ``-m "not integration"`` filter in the ``addopts`` list in
``pyproject.toml``.  To run them explicitly::

    pytest -m integration

Each test asserts a structural property of the result -- a property that is
true on every well-formed Linux host -- rather than any value that differs
between machines (specific IP addresses, interface names other than ``lo``,
etc.).

Fixture
-------
``require_ip`` (autouse) -- skips the whole class if the ``ip`` command is
absent.  This keeps CI green on environments where ``iproute2`` is not
installed.
"""

import pytest

from netcheck.network.interfaces import (
    _is_bridge,
    _is_tuntap,
    _is_veth,
    _is_vpn_by_name,
    _is_wireguard,
    detect_interface_type,
    get_interface_list,
)
from netcheck.core.enums import InterfaceType
from netcheck.utils.command import SystemCommandRunner, command_exists
from netcheck.utils.sysfs import SystemSysfsReader


@pytest.mark.integration
class TestRealInterfaceList:
    """Structural properties of the live interface list.

    Every well-formed Linux host satisfies these assertions regardless of
    its specific network configuration.
    """

    @pytest.fixture(autouse=True)
    def require_ip(self) -> None:
        """Skip all tests in this class if ``ip`` is not installed."""
        if not command_exists("ip"):
            pytest.skip("ip command not available")

    def test_interface_list_non_empty(self) -> None:
        """``get_interface_list`` must return at least one interface."""
        runner = SystemCommandRunner()
        names = get_interface_list(runner)
        assert len(names) > 0

    def test_loopback_always_present(self) -> None:
        """Every Linux host has a loopback interface named ``lo``."""
        runner = SystemCommandRunner()
        names = get_interface_list(runner)
        assert "lo" in names

    def test_loopback_classified_as_loopback(self) -> None:
        """``detect_interface_type`` must classify ``lo`` as LOOPBACK."""
        reader = SystemSysfsReader()
        itype = detect_interface_type("lo", frozenset(), reader)
        assert itype == InterfaceType.LOOPBACK


@pytest.mark.integration
class TestNonLoopbackClassification:
    """Every non-loopback interface must classify as a known type.

    This class provides the regression baseline for the sysfs-based detection
    chain.  On any desktop or server Linux host there will be at least one
    physical or virtual interface beyond ``lo``.  After the ARPHRD Ethernet
    detection was introduced (replacing the name-prefix fallback), every such
    interface should resolve to a type other than UNKNOWN -- UNKNOWN means no
    detection method fired, which indicates a bug or a sysfs file that is
    absent when it should not be.

    The test skips gracefully if only ``lo`` is present (e.g. a minimal
    container image), because asserting on a zero-length list is vacuously
    true and would give false confidence.

    Regression guard
    ----------------
    If the ARPHRD sysfs check regresses (e.g. ``type`` file absent), Ethernet
    interfaces that previously returned ETHERNET will return UNKNOWN and this
    test will catch it.  The test deliberately does not name the expected type
    for each interface -- it only asserts the absence of UNKNOWN -- so it
    remains valid across any hardware configuration.
    """

    @pytest.fixture(autouse=True)
    def require_ip(self) -> None:
        """Skip all tests in this class if ``ip`` is not installed."""
        if not command_exists("ip"):
            pytest.skip("ip command not available")

    def _non_loopback_names(self) -> list[str]:
        runner = SystemCommandRunner()
        return [n for n in get_interface_list(runner) if n != "lo"]

    def test_at_least_one_non_loopback_interface_present(self) -> None:
        """Skip the rest of this class early if the host has only loopback.

        A system with nothing but ``lo`` cannot exercise non-loopback
        classification at all.  Skipping here produces a clearly labelled
        skip rather than a vacuously-passing assertion.
        """
        names = self._non_loopback_names()
        if not names:
            pytest.skip("no non-loopback interfaces present on this host")
        assert len(names) > 0

    def test_no_non_loopback_interface_is_unknown(self) -> None:
        """Every non-loopback interface must resolve to a type other than UNKNOWN.

        UNKNOWN means the detection chain exhausted all methods without
        producing a result.  Any well-formed Linux interface -- Ethernet,
        wireless, VPN, cellular, tether, bridge, virtual -- should be
        classified by at least one of the sysfs checks or name-pattern checks
        in the chain.
        """
        names = self._non_loopback_names()
        if not names:
            pytest.skip("no non-loopback interfaces present on this host")

        reader = SystemSysfsReader()

        for name in names:
            itype = detect_interface_type(name, frozenset(), reader)
            assert itype != InterfaceType.UNKNOWN, (
                f"Interface '{name}' classified as UNKNOWN -- "
                f"the detection chain produced no result for it.  "
                f"Check that /sys/class/net/{name}/type is readable and "
                f"contains a recognised ARPHRD value."
            )

    def test_arphrd_type_file_readable_for_ethernet_interfaces(self) -> None:
        """For every interface the kernel classifies as Ethernet framing, the
        ``type`` sysfs file must be present and contain the string ``"1"``.

        This test validates the sysfs ABI assumption made by ``_is_ethernet``
        against the live kernel.  If any Ethernet-framing interface lacks this
        file the ARPHRD check cannot fire and the interface falls through to
        UNKNOWN.

        The test classifies each interface first, then checks sysfs for those
        that were classified as ETHERNET.  An interface classified via an
        earlier priority (WIRELESS, TETHER, etc.) is excluded -- those
        interfaces may also have ``type == "1"`` at the sysfs level (Ethernet
        framing is shared) but were correctly captured by a higher-priority
        check.
        """
        names = self._non_loopback_names()
        if not names:
            pytest.skip("no non-loopback interfaces present on this host")

        reader = SystemSysfsReader()

        ethernet_names = [
            name for name in names
            if detect_interface_type(name, frozenset(), reader)
               == InterfaceType.ETHERNET
        ]
        if not ethernet_names:
            pytest.skip("no ETHERNET interfaces detected on this host")

        for name in ethernet_names:
            value = reader.read_file(f"/sys/class/net/{name}", "type")
            assert value is not None, (
                f"Interface '{name}' classified as ETHERNET but "
                f"/sys/class/net/{name}/type is absent or unreadable."
            )
            assert value == "1", (
                f"Interface '{name}' classified as ETHERNET but "
                f"/sys/class/net/{name}/type contains '{value}', expected '1'."
            )


@pytest.mark.integration
class TestVpnSysfsPreValidation:
    """Pre-validation record for T4: sysfs VPN signal discovery (historical).

    This class was written before T4 was implemented.  It validated the
    sysfs signals that T4 would use, confirming the kernel ABI assumptions
    before any code was written.  It is retained as a historical record and
    regression guard; the post-implementation assertions live in
    ``TestVpnSysfsValidation`` below.

    Key finding documented here
    ---------------------------
    ProtonVPN's ``proton0`` interface is a WireGuard tunnel in a private
    network namespace.  The WireGuard kernel module does not populate
    ``abi_version`` for namespace-isolated interfaces.  T4 therefore uses
    ``type == "65534"`` (ARPHRD_NONE) with no ``tun_flags`` as the WireGuard
    signal, and ``tun_flags`` present as the TUN/TAP signal.
    See ``test_wireguard_or_tuntap_sysfs_file_present_for_vpn_interfaces``
    for the validated assertion and ``TestVpnSysfsValidation`` for the
    post-implementation assertions using the production helpers directly.
    """

    @pytest.fixture(autouse=True)
    def require_ip(self) -> None:
        """Skip all tests in this class if ``ip`` is not installed."""
        if not command_exists("ip"):
            pytest.skip("ip command not available")

    def _vpn_interface_names(self) -> list[str]:
        """Return names of interfaces currently classified as VPN."""
        runner = SystemCommandRunner()
        reader = SystemSysfsReader()
        names = get_interface_list(runner)
        return [
            name for name in names
            if detect_interface_type(name, frozenset(), reader)
               == InterfaceType.VPN
        ]

    def test_vpn_interfaces_present(self) -> None:
        """Skip the rest of this class early if no VPN is active.

        This is not a failure: the host simply has no VPN running.  The test
        is informational -- running ``pytest -m integration -v`` will show
        a SKIPPED line with the reason, making it obvious that VPN coverage
        was not exercised.
        """
        names = self._vpn_interface_names()
        if not names:
            pytest.skip(
                "no VPN interfaces active on this host -- "
                "start a VPN to exercise T4 pre-validation"
            )
        assert len(names) > 0

    def test_wireguard_or_tuntap_sysfs_file_present_for_vpn_interfaces(self) -> None:
        """Each name-unmatched VPN interface must expose a T4-detectable sysfs signal.

        T4 replaces the ``ip -d link show`` subprocess fallback for VPN
        interfaces that are NOT caught by the name-pattern check at priority 5.
        For those interfaces, sysfs signals are the only authoritative kernel
        data available.

        Interfaces caught by name first (e.g. ``pvpnksintrf0`` matching the
        ``pvpn*`` pattern, or ``tun0`` matching ``tun*``) never reach the
        fallback path.

        Design finding (observed 2026-03-07)
        -------------------------------------
        ProtonVPN's ``proton0`` interface is a WireGuard tunnel created inside
        a private network namespace.  Although the interface is visible in the
        global namespace (``ip -o link show`` lists it), the WireGuard kernel
        module does not populate ``abi_version`` in sysfs for namespace-isolated
        interfaces.  ``abi_version`` is therefore not a reliable universal signal
        for WireGuard.

        The robust alternative is to combine the ARPHRD ``type`` file (always
        present for every interface regardless of namespace) with ``tun_flags``
        (present only for TUN/TAP, never for WireGuard):

        - ``type == "65534"`` (ARPHRD_NONE) AND ``tun_flags`` absent -> WireGuard
        - ``tun_flags`` present -> TUN or TAP

        This test validates that signal: each name-unmatched VPN interface must
        expose either (a) ``tun_flags``, or (b) ARPHRD type 65534 (which covers
        both namespace-isolated and non-isolated WireGuard).  See TASKS.md T4
        for the updated design.
        """
        all_vpn_names = self._vpn_interface_names()
        if not all_vpn_names:
            pytest.skip("no VPN interfaces active on this host")

        # Only assert sysfs signals for interfaces that are NOT caught by the
        # name-pattern check.  Name-matched interfaces are handled at priority 5
        # and never reach T4's sysfs fallback path.
        sysfs_path_names = [n for n in all_vpn_names if not _is_vpn_by_name(n)]
        if not sysfs_path_names:
            pytest.skip(
                "all active VPN interfaces are name-matched (priority 5); "
                "no interfaces exercise T4's sysfs fallback path on this host"
            )

        reader = SystemSysfsReader()

        for name in sysfs_path_names:
            base = f"/sys/class/net/{name}"
            tun_flags = reader.read_file(base, "tun_flags")
            arphrd_type = reader.read_file(base, "type")
            # TUN/TAP: tun_flags present.
            # WireGuard (including namespace-isolated): type == "65534"
            # (ARPHRD_NONE) and no tun_flags.  abi_version is NOT used here
            # because it is absent for namespace-isolated WireGuard interfaces.
            detectable = tun_flags is not None or arphrd_type == "65534"
            assert detectable, (
                f"VPN interface '{name}' was not caught by the name-pattern "
                f"check and exposes no T4-detectable sysfs signal.  "
                f"tun_flags={tun_flags!r}, type={arphrd_type!r} "
                f"(expected tun_flags present, or type=='65534' (ARPHRD_NONE)).  "
                f"T4's sysfs detection will not fire for this interface.  "
                f"Investigate the kernel module and update the T4 design."
            )

    def test_wireguard_interface_exposes_abi_version(self) -> None:
        """Document which WireGuard interfaces expose ``abi_version`` in sysfs.

        This test checks ``wg``-prefixed interfaces only.  It is retained as
        documentation of the design finding that led to T4's final approach:
        ``abi_version`` is present for standard (non-namespace-isolated)
        WireGuard interfaces but absent for namespace-isolated ones such as
        ProtonVPN's ``proton0``.  T4 therefore does NOT use ``abi_version``
        as its detection signal -- it uses ``type == "65534"`` (ARPHRD_NONE)
        instead, which is always populated regardless of namespace.

        If this test runs and passes, it confirms ``abi_version`` exists for
        ``wg*``-named interfaces on this host, which is expected but not
        relied upon by the implementation.  If it skips, no ``wg*`` interface
        is active and the finding cannot be re-confirmed on this run.
        """
        runner = SystemCommandRunner()
        names = get_interface_list(runner)
        wg_names = [n for n in names if n.startswith("wg")]
        if not wg_names:
            pytest.skip("no wg* interfaces active on this host")

        reader = SystemSysfsReader()

        for name in wg_names:
            value = reader.read_file(f"/sys/class/net/{name}", "abi_version")
            assert value is not None, (
                f"WireGuard interface '{name}' does not expose "
                f"/sys/class/net/{name}/abi_version.  "
                f"T4's WireGuard detection relies on this file."
            )

    def test_tun_interface_exposes_tun_flags(self) -> None:
        """TUN interfaces must expose ``tun_flags`` specifically.

        Checks interfaces whose name starts with ``tun``.  Skips if none
        are active.  A ``tun``-prefixed interface that lacks ``tun_flags``
        would indicate that T4's TUN detection cannot fire on this host.
        """
        runner = SystemCommandRunner()
        names = get_interface_list(runner)
        tun_names = [n for n in names if n.startswith("tun")]
        if not tun_names:
            pytest.skip("no tun* interfaces active on this host")

        reader = SystemSysfsReader()

        for name in tun_names:
            value = reader.read_file(f"/sys/class/net/{name}", "tun_flags")
            assert value is not None, (
                f"TUN interface '{name}' does not expose "
                f"/sys/class/net/{name}/tun_flags.  "
                f"T4's TUN/TAP detection relies on this file."
            )


@pytest.mark.integration
class TestBridgeSysfsValidation:
    """Real-hardware sign-off for T2: sysfs ``bridge/`` directory detection.

    Validates that live bridge interfaces expose the sysfs signal that
    ``_is_bridge`` relies on: the presence of the ``bridge/`` directory
    under ``/sys/class/net/<iface>/``.

    Tests skip gracefully if no bridge interface is present.  Create a
    transient bridge before running::

        sudo ip link add br-test type bridge

    and delete it afterward::

        sudo ip link delete br-test
    """

    @pytest.fixture(autouse=True)
    def require_ip(self) -> None:
        """Skip all tests in this class if ``ip`` is not installed."""
        if not command_exists("ip"):
            pytest.skip("ip command not available")

    def _bridge_names(self) -> list[str]:
        """Return names of interfaces currently classified as BRIDGE."""
        runner = SystemCommandRunner()
        reader = SystemSysfsReader()
        names = get_interface_list(runner)
        return [
            n for n in names
            if detect_interface_type(n, frozenset(), reader)
               == InterfaceType.BRIDGE
        ]

    def test_bridge_interfaces_present(self) -> None:
        """Skip the rest of this class if no bridge is active."""
        names = self._bridge_names()
        if not names:
            pytest.skip(
                "no BRIDGE interfaces present -- "
                "run: sudo ip link add br-test type bridge"
            )
        assert len(names) > 0

    def test_bridge_sysfs_dir_present_for_bridge_interfaces(self) -> None:
        """Each BRIDGE interface must have the ``bridge/`` sysfs directory.

        Direct sysfs ABI assertion for T2: the kernel creates
        ``/sys/class/net/<iface>/bridge/`` exclusively for bridge master
        interfaces.  ``_is_bridge`` relies on ``dir_exists`` for this path.
        """
        names = self._bridge_names()
        if not names:
            pytest.skip("no BRIDGE interfaces present")

        reader = SystemSysfsReader()
        for name in names:
            assert reader.dir_exists(f"/sys/class/net/{name}/bridge"), (
                f"Bridge interface '{name}' lacks "
                f"/sys/class/net/{name}/bridge directory.  "
                f"The T2 sysfs signal is absent; _is_bridge cannot fire."
            )

    def test_is_bridge_returns_true_for_bridge_interfaces(self) -> None:
        """``_is_bridge`` must return ``True`` for every BRIDGE interface.

        Validates the production helper directly against the live kernel,
        independently of ``detect_interface_type``'s priority chain.
        """
        names = self._bridge_names()
        if not names:
            pytest.skip("no BRIDGE interfaces present")

        reader = SystemSysfsReader()
        for name in names:
            assert _is_bridge(name, reader) is True, (
                f"_is_bridge returned False for bridge interface '{name}'.  "
                f"Check /sys/class/net/{name}/bridge."
            )

    def test_loopback_lacks_bridge_sysfs_dir(self) -> None:
        """Regression guard: loopback must never have the ``bridge/`` dir.

        Loopback is always present and provides a stable anchor for
        asserting that non-bridge interfaces are not misclassified.
        """
        reader = SystemSysfsReader()
        assert not reader.dir_exists("/sys/class/net/lo/bridge"), (
            "Loopback 'lo' unexpectedly has a bridge/ sysfs directory."
        )
        assert _is_bridge("lo", reader) is False


@pytest.mark.integration
class TestVethSysfsValidation:
    """Real-hardware sign-off for T3: sysfs ``iflink``/``ifindex`` detection.

    Validates that live veth interfaces expose the sysfs signal that
    ``_is_veth`` relies on: ``iflink != ifindex`` under
    ``/sys/class/net/<iface>/``.

    Tests skip gracefully if no veth interface is present.  Create a
    transient pair before running::

        sudo ip link add veth-test0 type veth peer name veth-test1

    and delete it afterward::

        sudo ip link delete veth-test0
    """

    @pytest.fixture(autouse=True)
    def require_ip(self) -> None:
        """Skip all tests in this class if ``ip`` is not installed."""
        if not command_exists("ip"):
            pytest.skip("ip command not available")

    def _veth_names(self) -> list[str]:
        """Return names of interfaces currently classified as VIRTUAL."""
        runner = SystemCommandRunner()
        reader = SystemSysfsReader()
        names = get_interface_list(runner)
        return [
            n for n in names
            if detect_interface_type(n, frozenset(), reader)
               == InterfaceType.VIRTUAL
        ]

    def test_veth_interfaces_present(self) -> None:
        """Skip the rest of this class if no veth is active."""
        names = self._veth_names()
        if not names:
            pytest.skip(
                "no VIRTUAL interfaces present -- run: "
                "sudo ip link add veth-test0 type veth peer name veth-test1"
            )
        assert len(names) > 0

    def test_veth_iflink_differs_from_ifindex(self) -> None:
        """Each VIRTUAL interface must have ``iflink != ifindex`` in sysfs.

        Direct sysfs ABI assertion for T3: the kernel writes the peer
        interface index to ``iflink`` for each end of a veth pair, making
        it differ from the interface's own ``ifindex``.  ``_is_veth`` relies
        on this inequality.
        """
        names = self._veth_names()
        if not names:
            pytest.skip("no VIRTUAL interfaces present")

        reader = SystemSysfsReader()
        for name in names:
            base = f"/sys/class/net/{name}"
            ifindex = reader.read_file(base, "ifindex")
            iflink = reader.read_file(base, "iflink")
            assert ifindex is not None, (
                f"veth '{name}' lacks /sys/class/net/{name}/ifindex"
            )
            assert iflink is not None, (
                f"veth '{name}' lacks /sys/class/net/{name}/iflink"
            )
            assert int(ifindex) != int(iflink), (
                f"veth '{name}' has ifindex == iflink == {ifindex}.  "
                f"The T3 sysfs signal is absent; _is_veth cannot fire."
            )

    def test_is_veth_returns_true_for_virtual_interfaces(self) -> None:
        """``_is_veth`` must return ``True`` for every VIRTUAL interface.

        Validates the production helper directly against the live kernel,
        independently of ``detect_interface_type``'s priority chain.
        """
        names = self._veth_names()
        if not names:
            pytest.skip("no VIRTUAL interfaces present")

        reader = SystemSysfsReader()
        for name in names:
            assert _is_veth(name, reader) is True, (
                f"_is_veth returned False for virtual interface '{name}'.  "
                f"Check ifindex/iflink under /sys/class/net/{name}/."
            )

    def test_loopback_has_equal_iflink_ifindex(self) -> None:
        """Regression guard: loopback must have ``iflink == ifindex``.

        Every non-veth interface has equal values; ``_is_veth`` must return
        ``False`` for them.  Loopback is always present and provides a
        stable regression anchor.
        """
        reader = SystemSysfsReader()
        base = "/sys/class/net/lo"
        ifindex = reader.read_file(base, "ifindex")
        iflink = reader.read_file(base, "iflink")
        assert ifindex is not None, "loopback lacks /sys/class/net/lo/ifindex"
        assert iflink is not None, "loopback lacks /sys/class/net/lo/iflink"
        assert int(ifindex) == int(iflink), (
            f"Loopback 'lo' has ifindex={ifindex!r} != iflink={iflink!r}; "
            f"_is_veth would misclassify loopback as VIRTUAL."
        )
        assert _is_veth("lo", reader) is False


@pytest.mark.integration
class TestVpnSysfsValidation:
    """Real-hardware sign-off for T4: ``_is_wireguard`` and ``_is_tuntap``.

    Post-implementation complement to ``TestVpnSysfsPreValidation``.
    Validates that the T4 production helpers return the correct result for
    live VPN interfaces, and that the two helpers are mutually exclusive.

    Tests skip gracefully if no VPN is active.

    Key design finding (observed 2026-03-07)
    -----------------------------------------
    ProtonVPN's ``proton0`` is a WireGuard tunnel in a private network
    namespace.  The WireGuard kernel module does not populate ``abi_version``
    for namespace-isolated interfaces.  T4 uses ``type == "65534"``
    (ARPHRD_NONE) with ``tun_flags`` absent as the WireGuard signal.
    This finding is re-confirmed by ``test_wireguard_interfaces_have_arphrd_none``.
    """

    @pytest.fixture(autouse=True)
    def require_ip(self) -> None:
        """Skip all tests in this class if ``ip`` is not installed."""
        if not command_exists("ip"):
            pytest.skip("ip command not available")

    def _vpn_names(self) -> list[str]:
        """Return names of interfaces currently classified as VPN."""
        runner = SystemCommandRunner()
        reader = SystemSysfsReader()
        names = get_interface_list(runner)
        return [
            n for n in names
            if detect_interface_type(n, frozenset(), reader)
               == InterfaceType.VPN
        ]

    def test_vpn_interfaces_present(self) -> None:
        """Skip the rest of this class if no VPN is active."""
        if not self._vpn_names():
            pytest.skip(
                "no VPN interfaces active -- "
                "start a VPN to exercise T4 validation"
            )

    def test_sysfs_path_vpn_interfaces_fire_wireguard_or_tuntap(self) -> None:
        """Each name-unmatched VPN interface must trigger ``_is_wireguard``
        or ``_is_tuntap``.

        Name-matched interfaces (priority 5) never reach the T4 sysfs path
        and are excluded.  For the remainder, exactly one of the two helpers
        must return True; if neither does, T4's sysfs check is broken and
        the interface will be silently missed.

        The two helpers are mutually exclusive by construction: ``_is_tuntap``
        fires on ``tun_flags`` presence, and ``_is_wireguard`` requires its
        absence.  Both returning True is therefore impossible and indicates
        a logic error.
        """
        all_vpn = self._vpn_names()
        if not all_vpn:
            pytest.skip("no VPN interfaces active")

        sysfs_path = [n for n in all_vpn if not _is_vpn_by_name(n)]
        if not sysfs_path:
            pytest.skip(
                "all active VPN interfaces are name-matched (priority 5); "
                "no interfaces exercise the T4 sysfs path on this host"
            )

        reader = SystemSysfsReader()
        for name in sysfs_path:
            base = f"/sys/class/net/{name}"
            wireguard = _is_wireguard(name, reader)
            tuntap = _is_tuntap(name, reader)
            arphrd = reader.read_file(base, "type")
            flags = reader.read_file(base, "tun_flags")
            assert wireguard or tuntap, (
                f"VPN interface '{name}' is not name-matched and neither "
                f"_is_wireguard nor _is_tuntap returned True.  "
                f"type={arphrd!r}, tun_flags={flags!r}.  "
                f"T4 cannot detect this interface via sysfs."
            )
            assert not (wireguard and tuntap), (
                f"Both _is_wireguard and _is_tuntap returned True for "
                f"'{name}' -- impossible by construction (tun_flags is the "
                f"discriminant).  type={arphrd!r}, tun_flags={flags!r}."
            )

    def test_wireguard_interfaces_have_arphrd_none(self) -> None:
        """Interfaces detected as WireGuard must have ``type == '65534'``
        and no ``tun_flags`` in sysfs.

        Re-confirms the sysfs ABI assumptions of ``_is_wireguard`` against
        the live kernel.  Skips if no name-unmatched WireGuard interfaces
        are currently active.
        """
        all_vpn = self._vpn_names()
        if not all_vpn:
            pytest.skip("no VPN interfaces active")

        reader = SystemSysfsReader()
        wg_names = [
            n for n in all_vpn
            if not _is_vpn_by_name(n) and _is_wireguard(n, reader)
        ]
        if not wg_names:
            pytest.skip(
                "no name-unmatched WireGuard interfaces detected on this host"
            )

        for name in wg_names:
            arphrd = reader.read_file(f"/sys/class/net/{name}", "type")
            tun_flags = reader.read_file(f"/sys/class/net/{name}", "tun_flags")
            assert arphrd == "65534", (
                f"_is_wireguard fired for '{name}' but "
                f"/sys/class/net/{name}/type is {arphrd!r}, expected '65534'."
            )
            assert tun_flags is None, (
                f"_is_wireguard fired for '{name}' but "
                f"tun_flags is {tun_flags!r} (expected absent)."
            )
