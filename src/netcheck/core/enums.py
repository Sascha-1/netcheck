"""Domain enumerations for netcheck.

All categorical values are represented as enumerations to provide type safety
and eliminate arbitrary strings throughout the codebase.

Using ``StrEnum`` as the base class allows enum members to be used directly
wherever a plain string is expected without calling ``.value``, while
retaining full enum identity and membership checks.
"""

from enum import StrEnum

__all__ = ["DataStatus", "DnsLeakStatus", "EgressStatus", "InterfaceType"]


class DataStatus(StrEnum):
    """Status of a data field that may not always be available.

    Used throughout the domain model to distinguish between three distinct
    reasons a field may lack a value, replacing the ambiguous ``None``
    convention that conflates them.

    ``OK``
        Data is present and valid.  The accompanying value field is
        populated and meaningful.

    ``NOT_APPLICABLE``
        The field does not apply to this interface type by design.  No
        query was attempted.  Example: ``device`` for a loopback or VPN
        interface -- these types have no associated hardware.

    ``UNAVAILABLE``
        The field applies to this interface type, but data is currently
        absent for a legitimate operational reason.  The query was
        attempted and succeeded, but returned no data.  Examples:
        no default route is configured on the interface; a cellular modem
        has no SIM card inserted; an interface is administratively down.

    ``ERROR``
        The data source was queried and the query failed.  Examples:
        ``lspci`` timed out; ``resolvectl`` returned a non-zero exit code;
        ``ip route show dev`` produced no output at all.

    Display layer convention:
        - ``NOT_APPLICABLE`` renders as ``"N/A"``.
        - ``UNAVAILABLE``    renders as ``"--"``.
        - ``ERROR``          renders as ``"ERR"``.
        - ``OK``             renders the associated value.
    """

    OK = "ok"
    NOT_APPLICABLE = "not_applicable"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class InterfaceType(StrEnum):
    """Classification of a network interface by its role or physical technology.

    Detection priority applied by the hardware and network layers
    (highest to lowest):

    1. ``LOOPBACK``  -- interface name is exactly ``lo``.
    2. ``CELLULAR``  -- interface is listed as a ``(net)`` port by ModemManager.
    3. ``CELLULAR``  -- interface name starts with ``ww`` (WWAN predictable
                       naming prefix; fallback when ModemManager is unavailable).
    4. ``TETHER``    -- USB device whose kernel driver is in the tethering
                       driver list (e.g. ``cdc_ncm``, ``rndis_host``).
    5. ``VPN``       -- interface name contains a known VPN prefix, or the
                       kernel reports a tunnel link type.
    6. ``WIRELESS``  -- sysfs ``phy80211`` symlink is present.
    7. ``BRIDGE``    -- sysfs ``/sys/class/net/<iface>/bridge/`` directory is
                       present (authoritative kernel signal).
    8. ``VIRTUAL``   -- sysfs ``iflink != ifindex``; the kernel writes a
                       different peer index to ``iflink`` for veth pairs.
    9. ``VPN``       -- sysfs fallback: ``tun_flags`` present (TUN/TAP), or
                       ``type == "65534"`` (``ARPHRD_NONE``) with no
                       ``tun_flags`` (WireGuard, including namespace-isolated).
    10. ``ETHERNET`` -- sysfs ``/sys/class/net/<iface>/type`` equals ``1``
                       (``ARPHRD_ETHER``); authoritative kernel-assigned ARP
                       hardware type.
    11. ``UNKNOWN``  -- none of the above rules matched.
    """

    LOOPBACK = "loopback"
    ETHERNET = "ethernet"
    WIRELESS = "wireless"
    VPN = "vpn"
    CELLULAR = "cellular"
    TETHER = "tether"
    VIRTUAL = "virtual"
    BRIDGE = "bridge"
    UNKNOWN = "unknown"


class DnsLeakStatus(StrEnum):
    """Result of DNS leak analysis for a single interface.

    Every member answers the question: "What is the DNS leak situation for
    this interface?"  Members are ordered from most to least severe.

    ``LEAK``
        DNS queries are resolved by the ISP while a VPN is active.  The ISP
        can observe all queries, which defeats VPN privacy.  Immediate
        action is required.

    ``WARN``
        DNS queries are resolved by an unrecognised server while a VPN is
        active.  Manual investigation is needed.

    ``PUBLIC``
        DNS queries are resolved by a known public resolver (Cloudflare,
        Google, Quad9) while a VPN is active.  Traffic does not leak to the
        ISP, but the public resolver can observe all queries.

    ``OK``
        DNS queries are resolved by the VPN provider's resolver.  This is
        the ideal state when a VPN is active.

    ``DORMANT``
        A VPN is active on the system, but this interface has no currently
        active DNS resolution (``current_server`` is ``None``).
        systemd-resolved has correctly shifted the active designation to the
        VPN interface.  This interface cannot be leaking because it is not
        resolving any queries.

        This is a **positive security signal**: it confirms the VPN's DNS
        isolation is working.  It is distinct from ``NOT_APPLICABLE``
        because the VPN precondition *is* met -- the interface simply
        stepped aside.  Monitoring tools can use this to verify that all
        physical interfaces went dormant when the VPN connected.

    ``NOT_APPLICABLE``
        This interface is structurally or operationally excluded from DNS
        leak detection, regardless of VPN state.  Two conditions produce
        this status:

        - The interface type is not a DNS provider (loopback, VPN, bridge,
          virtual, unknown): such interfaces never act as DNS providers and
          cannot meaningfully step aside for a VPN.
        - The interface is a DNS-provider type (ethernet, wireless, cellular,
          tether) but has no current DNS activity in its present state
          (``query_status`` is not ``OK`` and ``current_server`` is ``None``):
          labelling it ``DORMANT`` would imply prior DNS activity that never
          occurred.

        Also used as a pre-computation placeholder until ``check_dns_leaks``
        assigns the real status.

    ``NO_VPN``
        No VPN interface is active on the system.  The concept of a DNS
        leak does not arise because there is no VPN tunnel to compare DNS
        servers against.  This is a run-level state that affects every
        interface when ``vpn_dns`` is empty.

        Distinct from ``NOT_APPLICABLE``: ``NO_VPN`` is a conclusive
        statement about the VPN state of the system.  ``NOT_APPLICABLE``
        is a statement about this interface's structural or operational
        participation in DNS routing, and can be assigned even when a VPN
        is active elsewhere on the system.
    """

    LEAK = "leak"
    WARN = "warn"
    PUBLIC = "public"
    OK = "ok"
    DORMANT = "dormant"
    NOT_APPLICABLE = "not_applicable"
    NO_VPN = "no_vpn"


class EgressStatus(StrEnum):
    """Status of the egress information for an interface.

    ``OK``
        The ipinfo.io API was queried successfully and all fields are
        populated.

    ``UNAVAILABLE``
        This interface is not the active egress path; the API was not
        queried.  The display layer renders data fields as ``"--"``.

    ``FAILED``
        The API was queried but returned an error or an unparseable
        response.  The display layer renders data fields as ``"ERR"``.

    Naming note -- ``FAILED`` vs ``ERROR``
    --------------------------------------
    ``DataStatus`` uses ``ERROR`` for a failed query.  This class uses
    ``FAILED`` for the same condition.  The asymmetry is intentional and
    must not be "fixed" by renaming: the serialized JSON value ``"failed"``
    is part of the public output schema.  Changing it to ``"error"`` would
    be a breaking change requiring a major version bump.

    Missing ``NOT_APPLICABLE``
    --------------------------
    ``DataStatus`` has a ``NOT_APPLICABLE`` member for fields that do not
    apply to a given interface type.  ``EgressStatus`` has no such member
    because there is no interface type for which egress is inapplicable.
    Every interface is either on the active egress path (``OK`` after a
    successful query) or is not (``UNAVAILABLE`` -- no query was made).
    The concept of "egress does not apply here" does not arise.
    """

    OK = "ok"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
