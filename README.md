# Netcheck

Network interface analysis tool for GNU/Linux.
Produces a color-coded terminal table or JSON report showing every network interface with its type, hardware device, internal and external IP addresses, DNS configuration, VPN status, and routing information.
No root privileges required.

## Output

**No VPN active** -- the tether interface is the active egress path (shown RED):

```
======================================================================================================================================================================================================================================================
Network Interface Analysis
======================================================================================================================================================================================================================================================
INTERFACE         TYPE          DEVICE                    INT IPv4            INT IPv6                        DNS                     EXT IPv4            EXT IPv6                        ISP                   COUNTRY     GATEWAY             METRIC
======================================================================================================================================================================================================================================================
lo                loopback      N/A                       127.0.0.1           --                              --                      --                  --                              --                    --          N/A                 N/A
wwp0s20f0u3       cellular      Quectel EM05-G            --                  --                              --                      --                  --                              --                    --          --                  --
wlp2s0            wireless      Intel Wi-Fi 6 AX200       192.0.2.30          2001:db8::30                    192.0.2.1               --                  --                              --                    --          192.0.2.1           600
enx001122334455   tether        Google Pixel 9            10.0.0.2            --                              10.0.0.1                203.0.113.1         2001:db8:1::1                   Example ISP           DE          10.0.0.1            100
======================================================================================================================================================================================================================================================
```

**VPN active** -- tether is the underlay carrier (CYAN), `proton0` is the encrypted tunnel (GREEN):

```
======================================================================================================================================================================================================================================================
Network Interface Analysis
======================================================================================================================================================================================================================================================
INTERFACE         TYPE          DEVICE                    INT IPv4            INT IPv6                        DNS                     EXT IPv4            EXT IPv6                        ISP                   COUNTRY     GATEWAY             METRIC
======================================================================================================================================================================================================================================================
lo                loopback      N/A                       127.0.0.1           --                              --                      --                  --                              --                    --          N/A                 N/A
wwp0s20f0u3       cellular      Quectel EM05-G            --                  --                              --                      --                  --                              --                    --          --                  --
wlp2s0            wireless      Intel Wi-Fi 6 AX200       192.0.2.30          2001:db8::30                    --                      --                  --                              --                    --          192.0.2.1           600
enx001122334455   tether        Google Pixel 9            10.0.0.2            --                              --                      --                  --                              --                    --          10.0.0.1            100
pvpnksintrf0      vpn           N/A                       100.85.0.1          fdeb:446c:912d::                --                      203.0.113.10        2001:db8:2::10                  Example VPN Ltd       NL          100.85.0.1          98
proton0           vpn           N/A                       10.2.0.2            2001:db8:3::2                   10.2.0.1                --                  --                              --                    --          --                  --
======================================================================================================================================================================================================================================================
```

Color coding and JSON `dns_leak_status` values:

| Color   | `dns_leak_status`  | Meaning |
|---------|--------------------|---------| 
| GREEN   | `ok`               | VPN tunnel active -- DNS via VPN provider |
| CYAN    | --                 | Physical interface carrying VPN traffic |
| RED     | --                 | Direct internet connection -- no VPN active |
| MAGENTA | `leak`             | DNS leak -- ISP sees all queries (fix immediately) |
| YELLOW  | `public`           | Public resolver (Cloudflare/Google/Quad9) -- no ISP leak, but suboptimal |
| YELLOW  | `warn`             | Unrecognised resolver -- investigate |
| none    | `dormant`          | VPN active; interface stepped aside, not currently routing DNS |
| none    | `not_applicable`   | Interface excluded from DNS leak detection (structural or operational) |
| none    | `no_vpn`           | No VPN active; DNS leak detection not applicable |

Table cell values:

| Value  | Meaning |
|--------|---------|
| `N/A`  | Field does not apply to this interface type by design (e.g. DEVICE for a VPN interface has no hardware) |
| `--`   | Field applies but data is currently unavailable (e.g. no default route, no IPv6 address) |
| `ERR`  | Query was attempted and failed |
| `(..)` | DNS configured but dormant -- not currently routing queries (JSON: `dormant`) |

## Features

- **Interface classification** -- loopback, ethernet, wireless, cellular
  modem, USB tether, bridge, virtual, VPN
- **Hardware identification** -- device names from PCI (lspci) and USB (lsusb)
  databases
- **Dual-stack IP** -- IPv4 and IPv6 addresses per interface
- **DNS analysis** -- configured servers and deterministic leak detection
- **External IP** -- public IPv4/IPv6, ISP, and country via ipinfo.io
- **VPN detection** -- server endpoint from static host routes in the kernel
  routing table; physical underlay carrier identified by lowest default-route
  metric
- **Cellular vs tethering** -- uses ModemManager to distinguish a built-in
  cellular modem from a USB-tethered phone
- **JSON export** -- structured output with metadata for scripting
- **No root required** -- all operations use unprivileged kernel APIs

## Requirements

**Python 3.12+** and **systemd-resolved** are required, along with these
system packages:

```bash
sudo apt install python3-requests iproute2 pciutils usbutils modemmanager
```

## Installation

```bash
git clone https://github.com/Sascha-1/netcheck.git
cd netcheck
make install
```

`make install` copies the launcher to `~/.local/bin/netcheck`, which is on
`PATH` by default in Debian and Linux Mint. On a fresh account where
`~/.local/bin` did not previously exist, log out and back in once, or run
`source ~/.profile`.

**Note:** `make install` records the absolute path of the project directory.
If you move or rename the directory after installation, `import netcheck` will
break silently. Re-run `make install` from the new location to fix it.

To uninstall:

```bash
make uninstall
```

## Usage

```bash
# Color table on stdout (default)
netcheck

# JSON to stdout
netcheck --export json

# JSON to file
netcheck --export json -o report.json

# Verbose debug logging to stderr
netcheck -v

# Also runnable as a Python module (requires make install)
python3 -m netcheck

# Run from source without installing (no make install required)
make run
make run ARGS="-v"
make run ARGS="--export json"
```

## DNS leak detection

Netcheck uses **configuration-based** leak detection -- it compares each
interface's active DNS server against categorised server lists rather than
timing actual queries.  Color coding and `dns_leak_status` JSON values are
documented in the [Output](#output) section above.

Public resolvers (Cloudflare `1.1.1.1`, Google `8.8.8.8`, Quad9 `9.9.9.9`)
are tracked separately from ISP DNS so users get actionable distinctions
rather than a binary pass/fail.

## JSON output

```json
{
  "metadata": {
    "timestamp": "2026-03-01T12:00:00+00:00",
    "tool": "netcheck",
    "version": "1.1.0",
    "interface_count": 6,
    "summary": {
      "vpn_active": true,
      "vpn_interface_count": 2,
      "dns_leak_detected": false
    }
  },
  "interfaces": [
    {
      "name": "proton0",
      "type": "vpn",
      "device": null,
      "device_status": "not_applicable",
      "ipv4": "10.2.0.2",
      "ipv4_status": "ok",
      "ipv6": "2001:db8:3::2",
      "ipv6_status": "ok",
      "dns_servers": ["10.2.0.1", "2001:db8:3::1"],
      "current_dns": "10.2.0.1",
      "dns_query_status": "ok",
      "dns_leak_status": "ok",
      "egress_status": "unavailable",
      "external_ipv4": null,
      "external_ipv6": null,
      "isp": null,
      "country": null,
      "routing_query_status": "unavailable",
      "gateway": null,
      "metric": null,
      "vpn_server_ip": "198.51.100.1",
      "vpn_server_ip_status": "ok",
      "is_vpn_underlay": false,
      "modem_state": null,
      "modem_state_reason": null
    }
  ]
}
```

### VPN active signal

`summary.vpn_active` is `true` when at least one VPN interface has a confirmed
server endpoint (a static host route to the server was found in the routing
table) or is the active egress path.

## Design principles

Netcheck is written to the standard of mission-critical diagnostic software.
The governing values are correctness over convenience, deterministic over
heuristic, single source of truth, and one stable environment done correctly.
All I/O is injected via Protocol interfaces; domain objects are frozen
dataclasses with enforced invariants; the output layer is a pure reader.

See `docs/DESIGN.md` for the full philosophy, the contributing rules, and the
architecture decision records.

## Development

Install development tools:

```bash
sudo apt install python3-pytest python3-pytest-cov python3-mypy python3-pylint
```

Available make targets:

```bash
make help               # show this target list
make check              # mypy + pylint + encoding + pytest + pytest-integration
make mypy               # mypy only
make pylint             # pylint only
make pytest             # pytest unit tests with coverage
make pytest-integration # pytest integration tests (requires real Linux hardware)
make encoding           # check all source files are ASCII-only
make clean              # remove cache and build artefacts
make install            # install netcheck to ~/.local/bin (no sudo, no pip)
make uninstall          # remove netcheck from ~/.local/bin
make run                # run from source without installing (ARGS=... optional)
```

Run `make help` for the authoritative current list.

Tests use `FakeCommandRunner`, `FakeSysfsReader`, and `FakeHttpClient` from
`tests/fakes.py`. Fixtures live in `tests/fixtures/` as plain text files
matching real command output.

## Privacy

`Netcheck` output contains network-identifying information. Be aware of the
following before sharing logs or JSON exports publicly:

- Interface names of the form `enxXXXXXXXXXXXX` encode the hardware MAC
  address directly (e.g. `enx8e1667d1b62d` encodes MAC `8e:16:67:d1:b6:2d`).
- Public IP addresses and ISP names appear in both terminal and JSON output.
- VPN server endpoints are included in the JSON export (`vpn_server_ip`).
- Sanitise or redact sensitive fields before sharing logs or JSON exports.

## Known limitations

### Multiple simultaneous VPNs with different servers

When two independent VPN tunnels to *different* servers are active at the same
time, both tunnel interfaces receive the same server IP -- whichever bypass
host route appears first in the routing table. Per-interface attribution would
require root (`wg show`, network namespace entry) or a VPN-client-specific
sidecar; neither is compatible with the no-root guarantee.

Single-VPN configurations are handled correctly, including multi-interface
setups such as ProtonVPN's kill-switch pair (`pvpnksintrf0` + `proton0`), where
both interfaces legitimately share one server endpoint.

### Network namespace isolation

Some VPN clients (e.g. ProtonVPN) isolate their tunnel interface inside a
private network namespace. Direct inspection of the tunnel's WireGuard state
(peer handshakes, allowed IPs) is not possible from the global namespace
without elevated privileges.

Netcheck is immune to this for the purpose of VPN *detection*: the VPN client
always injects a bypass host route for the server in the global routing table,
which `ip route show` reads without root. What remains unavailable is internal
tunnel state; the combination of a confirmed bypass route, active VPN DNS, and
correct egress IP is used as a reliable proxy for a live tunnel.

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | No interfaces found, missing required commands, or I/O error |

## License

AGPL-3.0-or-later
