# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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
