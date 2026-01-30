# Netcheck - Network Interface Analysis Tool

[![Python Version](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Tests](https://img.shields.io/badge/tests-171%20passing-brightgreen.svg)]()

A comprehensive network interface analysis tool for GNU/Linux

## 🗝️ Key Features

### 🌐 Comprehensive Network Info
- All network interfaces (Ethernet, Wi-Fi, VPN, USB tethering)
- IPv4 and IPv6 addresses
- Dual-stack IPv6 support (queries both IPv4 and IPv6 egress)
- DNS configuration per interface
- External IP and ISP information
- Gateway and routing metrics
- VPN underlay detection (which physical interface carries VPN traffic)

### 🎯 Deterministic Detection
- Hardware identification via PCI/USB vendor:device IDs
- Kernel-direct queries (sysfs, netlink)
- No heuristics or assumptions
- Works reliably on modern systems (kernel 6.12+, hardware 2015+)

### 🔒 DNS Leak Detection
- **Deterministic, configuration-based detection** - No timing dependencies
- Real-time monitoring of DNS traffic
- Detects when DNS queries leak to ISP while VPN is active
- Recognizes major public DNS providers (Cloudflare, Google, Quad9)
- Color-coded visual feedback (green = secure, red = leak detected)
- No root privileges required

### 📊 Clear Presentation
- Color-coded table output
- Visual leak indicators
- Detailed logging with `-v` flag
- Export logs to file for troubleshooting

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/Sascha-1/netcheck.git
cd netcheck

# Install system dependencies (Debian/Ubuntu)
sudo apt install iproute2 pciutils usbutils ethtool systemd-resolved

# Install Python dependencies
pip install -r requirements.txt

# Run the tool
./netcheck.py
```

### Requirements

**System:**
- OS: GNU/Linux (kernel 6.12+)
- Python: 3.12+
- DNS: systemd-resolved

**Commands Required:**
- `ip` - Network interface queries
- `lspci` - PCI device identification
- `lsusb` - USB device identification
- `ethtool` - Interface details
- `resolvectl` - DNS configuration
- `ss` - Network connection monitoring

## Usage Examples

### Basic Usage

```bash
# View all network interfaces
./netcheck.py

# Verbose output with detailed logging
./netcheck.py -v

# Save logs to file
./netcheck.py -v --log-file /tmp/netcheck.log

# Disable colored output
./netcheck.py --no-color

# View help
./netcheck.py --help
```

### Monitoring

```bash
# Continuous monitoring (updates every 5 seconds)
watch -n 5 ./netcheck.py

# Check for DNS leaks in scripts
./netcheck.py | grep "LEAK" && echo "WARNING: DNS leak detected!"

# Alert on leak detection
./netcheck.py | grep "LEAK" && notify-send "DNS Leak Detected!"
```

## Output Examples

### ✅ VPN Active - No Leak (Secure)

```
INTERFACE      TYPE       DEVICE           INTERNAL_IPv4   INTERNAL_IPv6         DNS_SERVER       DNS_LEAK EXTERNAL_IPv4   EXTERNAL_IPv6      ISP               COUNTRY GATEWAY         METRIC
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
lo             loopback   N/A              127.0.0.1       ::1                   --               --       --              --                 --                --      NONE            NONE
eth0           ethernet   Intel I219-V     192.168.8.111   N/A                   --               --       --              --                 --                --      192.168.8.1     100
tun0           vpn        N/A              10.2.0.2        2a07:b944::2:2        10.2.0.1         OK       159.26.108.89   2001:db8::1        Proton AG         SE      NONE            NONE
```

**Status:** Green row indicates VPN is active with no DNS leaks. ✅

### ⚠️ VPN Active - DNS Leak (Privacy Compromised)

```
INTERFACE      TYPE       DEVICE           INTERNAL_IPv4   INTERNAL_IPv6         DNS_SERVER       DNS_LEAK EXTERNAL_IPv4   EXTERNAL_IPv6      ISP               COUNTRY GATEWAY         METRIC
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
lo             loopback   N/A              127.0.0.1       ::1                   --               --       --              --                 --                --      NONE            NONE
eth0           ethernet   Intel I219-V     192.168.8.111   N/A                   192.168.8.1      LEAK     --              --                 --                --      192.168.8.1     100
tun0           vpn        N/A              10.2.0.2        2a07:b944::2:2        10.2.0.1         OK       159.26.108.89   2001:db8::1        Proton AG         SE      NONE            NONE
```

**Status:** Red "LEAK" indicates DNS queries are going to ISP despite VPN being active. ⚠️

### 🔓 No VPN (Direct Connection)

```
INTERFACE      TYPE       DEVICE           INTERNAL_IPv4   INTERNAL_IPv6         DNS_SERVER       DNS_LEAK EXTERNAL_IPv4   EXTERNAL_IPv6      ISP               COUNTRY GATEWAY         METRIC
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
lo             loopback   N/A              127.0.0.1       ::1                   --               --       --              --                 --                --      NONE            NONE
eth0           ethernet   Intel I219-V     192.168.8.111   2001:db8::100         192.168.8.1      --       217.140.201.219 2001:db8:cafe::1   Example ISP       FI      192.168.8.1     100
```

**Status:** Red row indicates direct connection without VPN protection.

## Understanding DNS Leaks

### What is a DNS Leak?

When you use a VPN, all your internet traffic should be routed through the VPN tunnel, including DNS queries. A **DNS leak** occurs when DNS queries bypass the VPN and go directly to your ISP's DNS servers, revealing which websites you visit.

### Why This Matters

Even with a VPN encrypting your traffic:
- Your ISP can see which websites you visit (via DNS queries)
- Your browsing history is exposed
- Your location might be revealed
- The privacy benefit of the VPN is defeated

### How Netcheck Detects Leaks

**Deterministic, configuration-based detection:**
1. **Categorizes DNS servers** into VPN DNS vs ISP DNS vs public DNS
2. **Checks configured DNS** for each interface
3. **When VPN active**, any use of ISP DNS = LEAK
4. **Recognizes public DNS** (1.1.1.1, 8.8.8.8, 9.9.9.9) as acceptable
5. **No timing dependencies** - based on actual configuration

**No root required** - reads systemd-resolved configuration only.

### DNS Leak Status Values

- `OK` (green) - No leak, using VPN DNS or public DNS
- `LEAK` (red) - DNS leak detected, using ISP DNS
- `WARN` (yellow) - Using unknown DNS servers
- `--` - Not applicable (no VPN active)

## Column Descriptions

| Column | Description | Data Source |
|--------|-------------|-------------|
| **INTERFACE** | Interface name (eth0, wlp8s0, tun0, etc.) | Kernel via `ip` |
| **TYPE** | Classification (ethernet, wireless, vpn, tether) | sysfs + kernel |
| **DEVICE** | Hardware device name (e.g., Intel I219-V) | lspci/lsusb |
| **INTERNAL_IPv4** | Local IPv4 address | Kernel routing |
| **INTERNAL_IPv6** | Global IPv6 address | Kernel routing |
| **DNS_SERVER** | Current active DNS server | systemd-resolved |
| **DNS_LEAK** | Leak detection status (OK/LEAK/WARN/--) | Configuration analysis |
| **EXTERNAL_IPv4** | Public IPv4 (active route only) | ipinfo.io API |
| **EXTERNAL_IPv6** | Public IPv6 (active route only) | ipinfo.io API |
| **ISP** | ISP name (active route only) | ipinfo.io API |
| **COUNTRY** | Country code (active route only) | ipinfo.io API |
| **GATEWAY** | Gateway IP | Kernel routing |
| **METRIC** | Route metric (lower = higher priority) | Kernel routing |

## Data Markers

- `--` = Not applicable
- `N/A` = Does not exist or cannot be determined
- `NONE` = No routes configured
- `DEFAULT` = Kernel-assigned default value
- `ERR` = Operation failed or API unreachable
- `OK` = No DNS leak detected
- `LEAK` = DNS leak detected
- `WARN` = Suspicious DNS activity

## Architecture

### Design Principles

1. **Deterministic Detection** - No heuristics, query actual hardware IDs and configuration
2. **Kernel-Direct** - All data from sysfs and netlink, not third-party tools
3. **Privacy First** - DNS leak detection without root privileges
4. **Separation of Concerns** - Data collection separate from display
5. **Modern Python** - Uses Python 3.12+ features (pathlib, walrus operator, match/case)

### File Structure

```
netcheck/
├── netcheck.py              # Main entry point
├── orchestrator.py          # Coordination module
├── display.py               # Table output formatting
├── models.py                # Data structures
├── config.py                # Configuration
├── enums.py                 # Type-safe enumerations
├── logging_config.py        # Structured logging
│
├── network/                 # Network detection
│   ├── detection.py         # Interface type + hardware ID
│   ├── configuration.py     # IPv4/IPv6 + routing
│   ├── dns.py               # DNS detection + leak checking
│   ├── egress.py            # External IP info (ipinfo.io)
│   └── vpn_underlay.py      # VPN tunnel carrier detection
│
├── utils/                   # Utilities
│   └── system.py            # Command execution + IP validation
│
└── tests/                   # Comprehensive test suite
    ├── conftest.py          # Shared fixtures
    └── test_*.py            # 171 tests covering all modules
```

### Module Responsibilities

**netcheck.py**: CLI entry point, argument parsing  
**orchestrator.py**: Coordinates all detection modules  
**display.py**: Table formatting, text cleaning (display-time only)  
**models.py**: InterfaceInfo, EgressInfo data structures  
**config.py**: Configuration constants  
**enums.py**: Type-safe constants  
**logging_config.py**: Structured logging setup  

**network/detection.py**: Interface type detection, hardware identification  
**network/configuration.py**: IPv4/IPv6 addresses, routing, gateways  
**network/dns.py**: DNS configuration, leak detection  
**network/egress.py**: External IP queries (dual-stack IPv4/IPv6)  
**network/vpn_underlay.py**: Detect which physical interface carries VPN traffic  

**utils/system.py**: Command execution, IP validation  

## Development

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-mock pytest-cov

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_network_dns.py -v

# Generate coverage report
pytest --cov=network --cov=utils --cov-report=html
firefox htmlcov/index.html
```

### Test Coverage

**171 tests** covering all modules:
- ✅ Enumerations (7 tests)
- ✅ Logging configuration (5 tests)
- ✅ Data models (5 tests)
- ✅ Network configuration (31 tests)
- ✅ Network detection (35 tests)
- ✅ DNS detection and leaks (27 tests)
- ✅ External IP queries (23 tests)
- ✅ System utilities (28 tests)
- ✅ VPN underlay detection (10 tests)

### Code Quality

**Standards:**
- PEP 8 compliant
- Type hints throughout
- Comprehensive docstrings
- Structured logging
- No silent failures

**Quality Tools:**
```bash
# Type checking
mypy netcheck.py orchestrator.py network/ utils/

# Code formatting
black --line-length 100 .

# Import sorting
isort .

# Security check
bandit -r . -ll
```

## Troubleshooting

### DNS Leak Shows "--" When VPN Active

**Cause:** DNS configuration not yet determined

**Solution:**
```bash
# Check DNS configuration
resolvectl status

# Verify VPN DNS is configured
resolvectl status tun0  # or your VPN interface

# Run netcheck again
./netcheck.py -v
```

### "resolvectl not found"

**Cause:** systemd-resolved not installed or not running

**Solution:**
```bash
sudo apt install systemd-resolved
sudo systemctl enable systemd-resolved
sudo systemctl start systemd-resolved
resolvectl status
```

### "ss command not found"

**Cause:** iproute2 package not installed

**Solution:**
```bash
sudo apt install iproute2
which ss  # Should output: /usr/bin/ss
```

### External IP Shows "ERR"

**Cause:** Cannot reach ipinfo.io API

**Solution:**
```bash
# Test API connectivity
curl https://ipinfo.io/json

# Test IPv6
curl https://v6.ipinfo.io/json

# Check firewall settings
# Check internet connection
# Verify DNS is working
```

### Interface Shows "N/A" for Device

**Cause:** Virtual interface (VPN, loopback) or hardware detection failed

**Note:** Virtual interfaces (VPN, loopback) correctly show "N/A" - they have no physical hardware.

## Known Limitations

- External IP info requires internet connectivity
- DNS detection requires systemd-resolved
- Requires modern Linux (kernel 6.12+, hardware 2015+)
- Shows only global scope IPv6 addresses
- IPv6 egress may show "--" if IPv6 not available

## Security & Privacy

### Privacy Focused

- **Local operation** - All detection happens on your machine
- **No telemetry** - No data sent anywhere (except ipinfo.io for external IP)
- **No tracking** - No analytics or reporting
- **Open source** - Audit the code yourself

### DNS Leak Detection

- Works without root privileges
- Reads systemd-resolved configuration only
- Deterministic - based on actual DNS settings
- Immediate feedback

### No Data Collection

The only external service used is ipinfo.io to determine your public IP address and ISP. This is optional - the tool works without it (external IP columns will show "--").

## FAQ

**Q: Do I need root/sudo to run this?**  
A: No. The tool runs with normal user privileges. You only need sudo to install system packages.

**Q: Does this work on Debian/Ubuntu/Mint?**  
A: Yes. Tested on Linux Mint 22.3 and should work on any modern Debian-based system with kernel 6.12+.

**Q: Will this work with ProtonVPN / NordVPN / etc?**  
A: Yes. The tool detects DNS leaks regardless of VPN provider. It works with ProtonVPN, NordVPN, Mullvad, and any other VPN.

**Q: Why do I need systemd-resolved?**  
A: For per-interface DNS configuration and resolution. Most modern Linux distributions use it by default.

**Q: Can I use this on a server?**  
A: Yes, but it's designed for desktop/workstation use where DNS leak detection matters most.

**Q: Does this work with IPv6?**  
A: Yes. Full IPv4 and IPv6 support for addresses, DNS, and leak detection. Dual-stack egress queries.

**Q: What if I use public DNS like 1.1.1.1 or 8.8.8.8?**  
A: Netcheck recognizes major public DNS providers (Cloudflare, Google, Quad9) and treats them as acceptable (shows "OK", not "LEAK").

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass (`pytest -v`)
5. Follow existing code style
6. Submit a pull request

## License

**AGPL v3** - See LICENSE file

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

## Author

Sascha

## Links

- **GitHub:** https://github.com/Sascha-1/netcheck
- **Issues:** https://github.com/Sascha-1/netcheck/issues
- **Documentation:** https://github.com/Sascha-1/netcheck/blob/main/README.md

---


