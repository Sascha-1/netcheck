"""Domain model dataclasses for netcheck.

All dataclasses in this module use ``frozen=True``.  Field mutation is a
compile-time error enforced by Python's dataclass machinery.  Post-construction
updates (DNS leak status, VPN underlay flags) use ``dataclasses.replace`` in
the orchestrator and in ``check_dns_leaks``; the output layer is a pure reader.

Egress status
-------------
``EgressInfo.status`` records why the data fields are ``None`` when they are.
``EgressStatus.UNAVAILABLE`` means this interface was not queried.
``EgressStatus.FAILED`` means the API was queried but returned an error.
``EgressStatus.OK`` means the query succeeded and all data fields are set.
The display layer uses ``status`` to choose between ``"--"`` and ``"ERR"``
when rendering absent data.
"""

from dataclasses import dataclass

from netcheck.core.enums import DataStatus, DnsLeakStatus, EgressStatus, InterfaceType


@dataclass(frozen=True)
class DeviceInfo:
    """Hardware device description with explicit collection status.

    Replaces the bare ``str | None`` device field so that callers can
    distinguish three distinct absence reasons:

    - ``DataStatus.NOT_APPLICABLE`` -- the interface type has no associated
      hardware (loopback, VPN, virtual, bridge).  No lookup was attempted.
    - ``DataStatus.UNAVAILABLE``    -- the interface could have hardware, but
      no PCI or USB device data was found in sysfs (e.g. a wireless or
      tether interface whose sysfs tree does not expose vendor/product IDs).
    - ``DataStatus.ERROR``          -- the hardware lookup tool (lspci, lsusb)
      was invoked but failed.
    - ``DataStatus.OK``             -- ``name`` is populated.

    ``name`` is non-``None`` if and only if ``status`` is ``DataStatus.OK``.
    This invariant is enforced at construction time by ``__post_init__``.
    The factory class-methods all satisfy it by construction; the check exists
    to catch any call-site that bypasses the factories and constructs
    ``DeviceInfo`` directly.
    """

    status: DataStatus
    name: str | None

    def __post_init__(self) -> None:
        """Enforce the name/status invariant at construction time.

        Raises:
            ValueError: If ``status`` is ``OK`` but ``name`` is ``None``, or
                if ``status`` is not ``OK`` but ``name`` is non-``None``.
                Either condition indicates a programming error at the call site.
        """
        if (self.status == DataStatus.OK) != (self.name is not None):
            raise ValueError(
                f"DeviceInfo invariant violated: "
                f"status={self.status!r} name={self.name!r}. "
                "name must be non-None if and only if status is OK."
            )

    @classmethod
    def not_applicable(cls) -> "DeviceInfo":
        """Return a ``DeviceInfo`` for interface types with no hardware.

        Use for loopback, VPN, virtual, and bridge interfaces.

        Returns:
            ``DeviceInfo`` with status ``NOT_APPLICABLE`` and ``name=None``.
        """
        return cls(status=DataStatus.NOT_APPLICABLE, name=None)

    @classmethod
    def unavailable(cls) -> "DeviceInfo":
        """Return a ``DeviceInfo`` when no hardware data exists in sysfs.

        Use when the interface is not USB-backed and has no PCI IDs -- the
        interface exists and hardware lookup was possible in principle, but
        sysfs contains no vendor/product information.

        Returns:
            ``DeviceInfo`` with status ``UNAVAILABLE`` and ``name=None``.
        """
        return cls(status=DataStatus.UNAVAILABLE, name=None)

    @classmethod
    def error(cls) -> "DeviceInfo":
        """Return a ``DeviceInfo`` when the hardware lookup tool failed.

        Use when sysfs IDs were found but the corresponding lspci or lsusb
        invocation returned no output or exited with an error.

        Returns:
            ``DeviceInfo`` with status ``ERROR`` and ``name=None``.
        """
        return cls(status=DataStatus.ERROR, name=None)

    @classmethod
    def ok(cls, name: str) -> "DeviceInfo":
        """Return a ``DeviceInfo`` with a successfully resolved hardware name.

        Args:
            name: Raw hardware description string from lspci or lsusb.

        Returns:
            ``DeviceInfo`` with status ``OK`` and ``name`` populated.
        """
        return cls(status=DataStatus.OK, name=name)


@dataclass(frozen=True)
class IPConfig:
    """IPv4 and IPv6 address configuration for an interface.

    Each protocol has an independent status field that distinguishes why the
    address may be absent:

    - ``DataStatus.UNAVAILABLE`` -- the command succeeded but reported no
                                   address for this protocol on this interface
                                   (e.g. IPv6 not configured, or interface
                                   administratively down).
    - ``DataStatus.ERROR``       -- the address query command failed.
    - ``DataStatus.OK``          -- the address field is populated.

    ``NOT_APPLICABLE`` is intentionally excluded: every interface type can
    in principle carry an IP address, so the concept does not arise here.

    ``ipv4_status == OK`` if and only if ``ipv4 is not None``.
    ``ipv6_status == OK`` if and only if ``ipv6 is not None``.
    Both invariants are enforced at construction time by ``__post_init__``.

    Factory methods
    ---------------
    ``IPConfig.unavailable()``          -- both protocols unavailable.
    ``IPConfig.error()``                -- both protocols errored.
    ``IPConfig.ok(ipv4, ipv6, *, ipv6_status)``
        -- ipv4 is present (OK); ipv6 may be present (OK) or absent
           (UNAVAILABLE or ERROR), controlled by ``ipv6_status``.
    """

    ipv4: str | None
    ipv4_status: DataStatus
    ipv6: str | None
    ipv6_status: DataStatus

    def __post_init__(self) -> None:
        """Enforce the address/status invariants at construction time.

        Raises:
            ValueError: If ``ipv4_status`` is ``OK`` but ``ipv4`` is ``None``,
                or ``ipv4_status`` is not ``OK`` but ``ipv4`` is non-``None``.
                Same check applied to ``ipv6`` / ``ipv6_status``.
        """
        if (self.ipv4_status == DataStatus.OK) != (self.ipv4 is not None):
            raise ValueError(
                f"IPConfig invariant violated: "
                f"ipv4_status={self.ipv4_status!r} ipv4={self.ipv4!r}. "
                "ipv4 must be non-None if and only if ipv4_status is OK."
            )
        if (self.ipv6_status == DataStatus.OK) != (self.ipv6 is not None):
            raise ValueError(
                f"IPConfig invariant violated: "
                f"ipv6_status={self.ipv6_status!r} ipv6={self.ipv6!r}. "
                "ipv6 must be non-None if and only if ipv6_status is OK."
            )

    @classmethod
    def unavailable(cls) -> "IPConfig":
        """Return an ``IPConfig`` when neither protocol returned an address.

        Use when the address query succeeded but the interface has no
        configured addresses for either protocol.

        Returns:
            ``IPConfig`` with both status fields ``UNAVAILABLE`` and both
            address fields ``None``.
        """
        return cls(
            ipv4=None,
            ipv4_status=DataStatus.UNAVAILABLE,
            ipv6=None,
            ipv6_status=DataStatus.UNAVAILABLE,
        )

    @classmethod
    def error(cls) -> "IPConfig":
        """Return an ``IPConfig`` when the address query command failed.

        Use when the runner returned ``None`` (subprocess failed, timed out,
        or was not found).

        Returns:
            ``IPConfig`` with both status fields ``ERROR`` and both address
            fields ``None``.
        """
        return cls(
            ipv4=None,
            ipv4_status=DataStatus.ERROR,
            ipv6=None,
            ipv6_status=DataStatus.ERROR,
        )

    @classmethod
    def ok(
        cls,
        ipv4: str,
        ipv6: str | None,
        *,
        ipv6_status: DataStatus = DataStatus.UNAVAILABLE,
    ) -> "IPConfig":
        """Return an ``IPConfig`` with a confirmed IPv4 address.

        IPv4 is always present when this factory is used (``ipv4_status``
        is set to ``OK`` unconditionally).  IPv6 is optional: supply
        ``ipv6`` and ``ipv6_status=DataStatus.OK`` when an IPv6 address is
        present, or leave ``ipv6=None`` and set ``ipv6_status`` to
        ``UNAVAILABLE`` (default) or ``ERROR`` when it is not.

        Args:
            ipv4: The IPv4 address string.
            ipv6: The IPv6 address string, or ``None`` when absent.
            ipv6_status: Status for the IPv6 field.  Must be ``OK`` when
                ``ipv6`` is non-``None``, and ``UNAVAILABLE`` or ``ERROR``
                when ``ipv6`` is ``None``.  Defaults to ``UNAVAILABLE``.

        Returns:
            ``IPConfig`` with ``ipv4_status=OK`` and the supplied ``ipv6``
            state.
        """
        return cls(
            ipv4=ipv4,
            ipv4_status=DataStatus.OK,
            ipv6=ipv6,
            ipv6_status=ipv6_status if ipv6 is None else DataStatus.OK,
        )


@dataclass(frozen=True)
class DNSConfig:
    """DNS server configuration, query status, and leak-detection result.

    ``query_status`` records the outcome of the ``resolvectl status <iface>``
    call:

    - ``DataStatus.OK``          -- at least one DNS server was found;
                                   ``servers`` is non-empty.
    - ``DataStatus.UNAVAILABLE`` -- command succeeded but reported no DNS
                                   servers for this interface; ``servers``
                                   is an empty tuple.
    - ``DataStatus.ERROR``       -- runner returned ``None`` (subprocess
                                   failed, timed out, or was not found).

    ``servers`` holds every DNS server address reported by
    ``resolvectl status <interface>``.  An empty tuple indicates that
    systemd-resolved has no DNS configuration for this interface.

    ``current_server`` is the address that systemd-resolved is actively
    using for this interface, or ``None`` when not reported.  Note that
    this field may be ``None`` even when ``servers`` is non-empty: when a
    VPN is active, systemd-resolved shifts the "current" designation to the
    VPN interface, leaving physical interfaces with no current server.

    ``leak_status`` is populated by ``check_dns_leaks`` after all interfaces
    have been collected; it requires a system-wide view of VPN and ISP DNS
    servers to be meaningful.  Until then it holds the placeholder value
    ``DnsLeakStatus.NOT_APPLICABLE``.
    """

    query_status: DataStatus
    servers: tuple[str, ...]
    current_server: str | None
    leak_status: DnsLeakStatus


@dataclass(frozen=True)
class RoutingInfo:
    """Default gateway, route metric, and query status for an interface.

    ``query_status`` records the outcome of the ``ip route show dev <iface>``
    call:

    - ``DataStatus.OK``          -- a default route entry was found.
                                   ``metric`` is set.  ``gateway`` is the
                                   ``via`` address when present, or ``None``
                                   for a directly-connected route (no ``via``
                                   keyword in the routing table entry).
    - ``DataStatus.UNAVAILABLE`` -- command succeeded but no default route
                                   exists for this interface.  ``gateway``
                                   and ``metric`` are ``None``.
    - ``DataStatus.ERROR``       -- runner returned ``None``; ``gateway``
                                   and ``metric`` are ``None``.

    ``metric`` is always the literal integer value present in the routing
    table when a default route exists.  When the ``metric`` keyword is absent
    from the route entry, the kernel implicitly uses ``0``; netcheck reads
    this deterministically rather than substituting a placeholder string.
    """

    query_status: DataStatus
    gateway: str | None
    metric: int | None


@dataclass(frozen=True)
class VPNInfo:
    """VPN-specific metadata for an interface.

    ``server_ip`` is the public IP address of the remote VPN endpoint,
    determined from static host routes in the global kernel routing table,
    as injected by the VPN client.

    ``server_ip_status`` records why ``server_ip`` may be absent:

    - ``DataStatus.UNAVAILABLE`` -- the routing table was queried
                                   successfully but no qualifying static
                                   host route was found.
    - ``DataStatus.ERROR``       -- the ``ip route show`` command failed.
    - ``DataStatus.OK``          -- ``server_ip`` is populated.

    ``NOT_APPLICABLE`` is used for non-VPN interfaces: the VPN server
    endpoint concept does not apply to loopback, ethernet, wireless, etc.
    For those interfaces, ``server_ip_status`` is set to ``NOT_APPLICABLE``
    and no routing-table query is performed.

    ``server_ip_status == OK`` if and only if ``server_ip is not None``.
    This invariant is enforced at construction time by ``__post_init__``.

    ``is_vpn_underlay`` is ``True`` when this physical interface is the underlay
    that carries an active VPN tunnel's traffic (i.e. the tunnel's packets
    travel over this interface before encryption/decryption).

    Factory methods
    ---------------
    ``VPNInfo.unavailable()``        -- no qualifying route found.
    ``VPNInfo.error()``              -- route query failed.
    ``VPNInfo.ok(server_ip)``        -- server endpoint confirmed.
    All three accept an optional ``is_vpn_underlay`` keyword argument
    (default ``False``).
    """

    server_ip: str | None
    server_ip_status: DataStatus
    is_vpn_underlay: bool

    def __post_init__(self) -> None:
        """Enforce the server_ip/status invariant at construction time.

        Raises:
            ValueError: If ``server_ip_status`` is ``OK`` but ``server_ip``
                is ``None``, or ``server_ip_status`` is not ``OK`` but
                ``server_ip`` is non-``None``.
        """
        if (self.server_ip_status == DataStatus.OK) != (self.server_ip is not None):
            raise ValueError(
                f"VPNInfo invariant violated: "
                f"server_ip_status={self.server_ip_status!r} "
                f"server_ip={self.server_ip!r}. "
                "server_ip must be non-None if and only if server_ip_status is OK."
            )

    @classmethod
    def unavailable(cls, *, is_vpn_underlay: bool = False) -> "VPNInfo":
        """Return a ``VPNInfo`` when no VPN server route was found.

        Use when ``ip route show`` succeeded but contained no qualifying
        static host route to a public address.

        Args:
            is_vpn_underlay: Whether this interface carries VPN tunnel traffic.

        Returns:
            ``VPNInfo`` with ``server_ip_status=UNAVAILABLE``,
            ``server_ip=None``.
        """
        return cls(
            server_ip=None,
            server_ip_status=DataStatus.UNAVAILABLE,
            is_vpn_underlay=is_vpn_underlay,
        )

    @classmethod
    def error(cls, *, is_vpn_underlay: bool = False) -> "VPNInfo":
        """Return a ``VPNInfo`` when the route query command failed.

        Use when the runner returned ``None`` (subprocess failed or was not
        found).

        Args:
            is_vpn_underlay: Whether this interface carries VPN tunnel traffic.

        Returns:
            ``VPNInfo`` with ``server_ip_status=ERROR``, ``server_ip=None``.
        """
        return cls(
            server_ip=None,
            server_ip_status=DataStatus.ERROR,
            is_vpn_underlay=is_vpn_underlay,
        )

    @classmethod
    def not_applicable(cls, *, is_vpn_underlay: bool = False) -> "VPNInfo":
        """Return a ``VPNInfo`` for interface types that cannot be VPN endpoints.

        Use for loopback, ethernet, wireless, cellular, tether, bridge, and
        virtual interfaces.  No routing-table query was attempted; the
        concept of a VPN server endpoint does not apply.

        Args:
            is_vpn_underlay: Whether this interface carries VPN tunnel traffic.

        Returns:
            ``VPNInfo`` with ``server_ip_status=NOT_APPLICABLE``,
            ``server_ip=None``.
        """
        return cls(
            server_ip=None,
            server_ip_status=DataStatus.NOT_APPLICABLE,
            is_vpn_underlay=is_vpn_underlay,
        )

    @classmethod
    def ok(cls, server_ip: str, *, is_vpn_underlay: bool = False) -> "VPNInfo":
        """Return a ``VPNInfo`` with a confirmed VPN server endpoint.

        Args:
            server_ip: Public IP address of the VPN server, from a static
                host route in the kernel routing table.
            is_vpn_underlay: Whether this interface carries VPN tunnel traffic.

        Returns:
            ``VPNInfo`` with ``server_ip_status=OK`` and ``server_ip``
            populated.
        """
        return cls(
            server_ip=server_ip,
            server_ip_status=DataStatus.OK,
            is_vpn_underlay=is_vpn_underlay,
        )


@dataclass(frozen=True)
class ModemInfo:
    """Cellular modem state reported by ModemManager.

    This dataclass is attached to ``InterfaceInfo`` only when
    ``interface_type`` is ``InterfaceType.CELLULAR``.  It may be ``None``
    for a CELLULAR interface when ModemManager does not report the modem
    (e.g. no SIM card is inserted and the modem is in a failed state).

    ``state`` mirrors the ``modem.generic.state`` field from
    ``mmcli -m <index> -K`` (e.g. ``"registered"``, ``"connected"``,
    ``"failed"``).  It is ``None`` when the key is absent from mmcli output
    or when mmcli returned no output at all.

    ``state_reason`` mirrors ``modem.generic.state-failed-reason`` and is
    ``None`` unless the modem is in a failed state (e.g. ``"sim-missing"``).

    ``state`` uses ``str`` rather than an enum because ModemManager state
    strings are controlled by an external daemon whose vocabulary can expand
    across versions.  Using ``str`` avoids the maintenance burden of keeping
    a local enum in sync with upstream, at the cost of type safety on a
    bounded set.
    """

    state: str | None
    state_reason: str | None


@dataclass(frozen=True)
class EgressInfo:
    """Public IP address, ISP, and country from the ipinfo.io API.

    ``status`` records the outcome of the API query and governs how the
    display layer renders the data fields when they are ``None``:

    - ``EgressStatus.OK``          -- all data fields are populated.
    - ``EgressStatus.UNAVAILABLE`` -- interface was not the active egress
                                     path; data fields are ``None``; display
                                     renders as ``"--"``.
    - ``EgressStatus.FAILED``      -- API was queried but failed; data fields
                                     are ``None``; display renders as
                                     ``"ERR"``.

    The ``isp`` field contains the raw value returned by ipinfo.io, which
    includes an AS number prefix (e.g. ``"AS3320 Deutsche Telekom AG"``).
    The display layer is responsible for stripping the AS number.

    Factory methods
    ---------------
    ``EgressInfo.create_unavailable()`` -- for interfaces not on the egress
    path.

    ``EgressInfo.create_failed()`` -- for a failed API query.
    """

    status: EgressStatus
    external_ip: str | None
    external_ipv6: str | None
    isp: str | None
    country: str | None

    @classmethod
    def create_unavailable(cls) -> "EgressInfo":
        """Return an EgressInfo for an interface that was not queried.

        Use this for every interface that is not the active egress path.

        Returns:
            ``EgressInfo`` with ``status=UNAVAILABLE`` and all data fields
            ``None``.
        """
        return cls(
            status=EgressStatus.UNAVAILABLE,
            external_ip=None,
            external_ipv6=None,
            isp=None,
            country=None,
        )

    @classmethod
    def create_failed(cls) -> "EgressInfo":
        """Return an EgressInfo for a failed API query.

        Use this when the active egress interface was identified but the
        ipinfo.io API call returned an error or unparseable response.

        Returns:
            ``EgressInfo`` with ``status=FAILED`` and all data fields
            ``None``.
        """
        return cls(
            status=EgressStatus.FAILED,
            external_ip=None,
            external_ipv6=None,
            isp=None,
            country=None,
        )


@dataclass(frozen=True)
class InterfaceInfo:
    """Complete network information for one interface.

    Groups all sub-domain objects for a single network interface.  Each
    field group is a frozen dataclass in its own right.

    ``name``           -- Interface name string (e.g. ``"eth0"``).
    ``interface_type`` -- Classification from ``InterfaceType``.
    ``device``         -- Hardware description and lookup status.
    ``ip``             -- Internal IPv4 and IPv6 addresses.
    ``dns``            -- DNS server configuration and leak status.
    ``egress``         -- Public IP, ISP, and country.
    ``routing``        -- Default gateway, metric, and query status.
    ``vpn``            -- VPN endpoint and underlay carrier flag.
    ``modem``          -- Modem state (cellular interfaces only; else ``None``).

    ``modem`` note
    --------------
    For a CELLULAR interface whose modem is in a failed state (e.g. no SIM
    inserted and the modem is not reported by ``mmcli``),
    ``modem`` may be ``None`` even for a CELLULAR interface.  The display layer
    must handle this case.
    """

    name: str
    interface_type: InterfaceType
    device: DeviceInfo
    ip: IPConfig
    dns: DNSConfig
    egress: EgressInfo
    routing: RoutingInfo
    vpn: VPNInfo
    modem: ModemInfo | None
