# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Release definition:** a release is a commit that bumps `VERSION` in
> `src/netcheck/config/__init__.py`, is tagged `vX.Y.Z`, and has its
> `[Unreleased]` section promoted to a dated `[X.Y.Z]` entry in this file.
> Pushing commits to GitHub -- including commits that add to `[Unreleased]`
> -- does not constitute a release.  The version string reported by the
> running binary reflects whatever `VERSION` was at the last tagged commit,
> not the state of the working tree.

---

## [Unreleased]

### Added

**DNS leak detection**

- `DnsLeakStatus.NO_VPN` (`"no_vpn"`) — new enum member that replaces
  `NOT_APPLICABLE` in the specific case where no VPN interface is active
  system-wide.  `NOT_APPLICABLE` now means only structural or operational
  exclusion of this interface from leak detection, regardless of VPN state.
  `NO_VPN` is a conclusive statement about the VPN state of the whole system;
  `NOT_APPLICABLE` is a statement about this interface's participation in DNS
  routing.  Downstream consumers that treat unknown values as `not_applicable`
  are unaffected by the addition.

- `DnsLeakStatus.ISOLATED` (`"isolated"`) — new enum member for DNS-provider
  interfaces that have no DNS servers configured and no current DNS activity
  while a VPN is active on the system.  This covers two observationally
  identical situations: a VPN client that explicitly strips DNS server
  configuration from physical interfaces during tunnel establishment (e.g.
  ProtonVPN), and a physical interface that has no DNS in its current
  operational state (e.g. a cellular modem with no SIM inserted) while a VPN
  is active elsewhere.  The tool cannot distinguish these cases from observable
  state alone and uses `ISOLATED` to represent both truthfully.
  `ISOLATED` is distinct from `DORMANT`, which requires at least one
  configured server address (evidence that the interface stepped aside from a
  DNS role).  Like `DORMANT`, `ISOLATED` is a positive security signal on
  physical interfaces: the interface is not resolving any queries while the
  VPN is running.  Downstream consumers that treat unknown values as
  `not_applicable` are unaffected by the addition.

### Changed

**JSON schema** *(breaking)*

- `carries_vpn` renamed to `is_vpn_underlay` in every interface record.
  The old name described the field from the VPN's point of view (the VPN
  carries traffic over this interface); the new name describes it from the
  interface's point of view (this interface is the physical underlay carrying
  VPN traffic), which matches how the field is read in the display and export
  layers.  Downstream JSON consumers must update the field name.

**DNS leak detection**

- `dns_leak_status: "not_applicable"` now means only that this specific
  interface is structurally or operationally excluded from leak detection --
  either because its type never acts as a DNS provider (loopback, VPN, bridge,
  virtual, unknown), or because it is a DNS-provider type with no current DNS
  activity in its present state.  The VPN-absence case is now reported as
  `"no_vpn"` (see Added above).

- VPN name-substring detection is now driven by the `VPN_NAME_SUBSTRINGS`
  constant in `src/netcheck/config/__init__.py`, eliminating a hardcoded
  `"vpn"` string inside `src/netcheck/network/interfaces.py`.  Behaviour is
  unchanged; the constant is now the single authoritative source for
  name-based VPN detection alongside the existing `VPN_NAME_PREFIXES`.

**Output**

- Table legend entry for `dns:not_applicable` updated from "No VPN active, or
  interface not currently routing DNS" to "Interface excluded from DNS leak
  detection", accurately reflecting the narrowed semantics after the
  introduction of `no_vpn`.
- Table legend entry for `dns:no_vpn` added: "No VPN active; DNS leak
  detection not applicable".

**Documentation**

- README: new `### dns_leak_detected signal` subsection added under JSON
  output, documenting that `dns_leak_detected: false` is a security-positive
  signal only when `vpn_active: true`.  When `vpn_active: false` the field
  confirms there is no active VPN through which a leak could occur, but does
  not imply DNS privacy.  A three-row lookup table makes the combinations
  explicit for monitoring systems and scripting consumers.
- README: colour table updated to reflect the `not_applicable` / `no_vpn`
  distinction; `is_vpn_underlay` field name corrected in the JSON example.

### Fixed

**DNS leak detection**

- `DNSConfig` docstring for `OK` and `UNAVAILABLE` states corrected.  The
  `OK` bullet previously omitted the requirement that `servers` is non-empty;
  the `UNAVAILABLE` bullet did not state that `servers` is empty.

- `_with_leak_status` previously contained two independent guard conditions
  written inline, both producing a `NOT_APPLICABLE` assignment.  Extracted
  into a `_should_skip_leak_detection(iface)` helper with a single assignment
  site and a full docstring explaining both conditions and their shared
  `current_server is None` sub-condition.

**Test coverage**

- `tests/unit/test_orchestrator.py`: added test covering the no-carrier branch
  (lines 132--133) where `_apply_vpn_underlay` sets `vpn_server_ip` on VPN
  interfaces even when no physical underlay carrier is found.
- `tests/unit/utils/test_sysfs.py`: added tests for three OS-error paths in
  `SystemSysfsReader` -- `read_file` target-is-directory, `read_link_name`
  permission-denied, and `dir_exists` permission-denied.
- `tests/unit/network/test_addressing.py`: added four tests covering the
  `False` arms of `current_iface is not None` and `if addr_match:` in both
  `get_all_ipv4_addresses` and `get_all_ipv6_addresses`, bringing
  `addressing.py` to 100% branch coverage.

---

## [1.1.0] - 2026-03-09

Initial public release.

### Added

**Core tool**

- Color-coded terminal table showing all network interfaces with columns for
  interface name, type, hardware device, internal IPv4/IPv6, DNS server,
  external IPv4/IPv6, ISP, country, gateway, and metric.
- JSON export (`--export json`) with a metadata block containing timestamp,
  version, interface count, and a VPN/DNS-leak summary.
- Verbose debug logging to stderr (`-v`).
- Preflight check that reports all missing required commands before attempting
  any network queries, with the Debian/Ubuntu package name needed to fix each.

**Interface classification**

- Eight interface types: loopback, ethernet, wireless, VPN, cellular, tether,
  bridge, virtual.
- Detection uses ModemManager, sysfs symlinks, and kernel link type (in that
  priority order) before falling back to interface name prefixes.
  No root required.
- Cellular modems (via ModemManager) are distinguished from USB-tethered
  phones; both produce correct hardware device names via `lsusb`.
- Compatible with the `mmcli -K` output format used by ModemManager as shipped
  in Debian 12 (Bookworm) and later, and with the single-line format used by
  Debian 11 (Bullseye) and earlier.

**VPN detection**

- VPN server endpoint identified from static host routes in the global routing
  table (`ip route show`).  Protocol-agnostic: works for WireGuard and OpenVPN
  without root and without crossing network namespace boundaries.
- Physical underlay carrier identified as the lowest-metric gateway-bearing
  interface.
- ProtonVPN kill-switch architecture (pvpnksintrf0 + proton0) handled
  correctly: kill-switch interface is not colored GREEN; real tunnel interface
  is colored GREEN when VPN DNS is active.

**DNS leak detection**

- Configuration-based: compares each interface's active DNS server against
  categorised server lists.  Does not time actual queries.
- Six leak states: OK (VPN DNS), PUBLIC (Cloudflare/Google/Quad9), LEAK (ISP
  DNS), WARN (unrecognised server), DORMANT (stepped aside for VPN),
  NOT_APPLICABLE (interface type does not participate in DNS routing).

**JSON export**

- Every interface record includes `ipv4_status`, `ipv6_status`, and
  `vpn_server_ip_status` fields, allowing programmatic consumers to distinguish
  unavailable data from error conditions without parsing display strings.
- `dns_servers` is `null` when `dns_query_status` is not `ok`, distinguishing
  a successful query that found no servers from a query that was never made
  or failed.

**Design**

- All I/O dependencies (subprocess, sysfs, HTTP) injected via Protocol
  interfaces (`CommandRunner`, `SysfsReader`, `HttpClient`).  No
  `unittest.mock.patch` anywhere in the test suite.
- All domain dataclasses frozen (`frozen=True`).  The orchestrator never
  mutates interface records; updates use `dataclasses.replace`.
- `DataStatus` enum on all query-result fields distinguishes NOT_APPLICABLE,
  UNAVAILABLE, ERROR, and OK without sentinel strings in domain objects.
- Display formatting (device name cleanup, ISP string cleanup, column
  truncation) isolated in `src/netcheck/output/formatters.py`.
- `render_table` is a pure function returning a string; `format_table` is a
  thin I/O wrapper around it.
- 688 unit tests at release; mypy strict; pylint 10.0/10.

**Project layout**

- `src/` layout per PEP 517/518.  The installable Python package lives at
  `src/netcheck/`.  Writing `$(CURDIR)/src` into the `.pth` file eliminates
  the import-shadowing hazard of a flat layout.
- `make run` target runs Netcheck from the working tree without installing.
  Accepts optional arguments via `ARGS`: `make run ARGS="-v"`.
- `make logs` target captures VPN-off and VPN-on snapshots interactively to
  `logs/`, producing JSON reports, table output, and verbose debug logs for
  both states.
- `make all` target runs `make check` followed by `make logs`, writing the
  check output to `logs/check.log`.
