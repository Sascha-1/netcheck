# Netcheck - Network Interface Analysis Tool

[![Python Version](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Tests](https://img.shields.io/badge/tests-171%20passing-brightgreen.svg)]()

A comprehensive network interface analysis tool for GNU/Linux with DNS leak detection and VPN tunnel inspection.

## Key Features

### Comprehensive Network Info
- All network interfaces (Ethernet, Wi-Fi, USB tethering, VPN)
- IPv4 and IPv6 addresses
- Dual-stack IPv6 support (queries both IPv4 and IPv6 egress)
- DNS configuration per interface
- External IP and ISP information
- Gateway and routing metrics
- VPN underlay detection (which physical interface carries VPN traffic)

### Deterministic Detection
- Hardware identification via PCI/USB vendor:device IDs
- Kernel-direct queries (sysfs, netlink)
- No heuristics or assumptions
- Works reliably on modern systems (kernel 6.12+, hardware 2015+)

### DNS Leak Detection
- Deterministic, configuration-based detection
- Real-time monitoring of DNS traffic
- Detects when DNS queries leak to ISP while VPN is active
- Recognizes major public DNS providers (Cloudflare, Google, Quad9)
- Color-coded visual feedback (green = secure, red = leak detected)
- No root privileges required

### Clear Presentation
- Color-coded table output
- Visual leak indicators
- Detailed logging with `-v` flag
- Export to JSON/CSV formats

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

# Export to JSON
./netcheck.py --export json --output network.json

# Export to CSV
./netcheck.py --export csv --output network.csv
```

### Monitoring

```bash
# Continuous monitoring (updates every 5 seconds)
watch -n 5 ./netcheck.py

# Check for DNS leaks in scripts
./netcheck.py | grep "LEAK" && echo "WARNING: DNS leak detected!"
```

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
1. Categorizes DNS servers into VPN DNS vs ISP DNS vs public DNS
2. Checks configured DNS for each interface
3. When VPN active, any use of ISP DNS = LEAK
4. Recognizes public DNS (1.1.1.1, 8.8.8.8, 9.9.9.9) as acceptable
5. No timing dependencies - based on actual configuration

**No root required** - reads systemd-resolved configuration only.

### DNS Leak Status Values

- `OK` (green) - No leak, using VPN DNS or public DNS
- `LEAK` (red) - DNS leak detected, using ISP DNS
- `WARN` (yellow) - Using unknown DNS servers
- `--` - Not applicable (no VPN active)

## Architecture

### Design Principles

1. **Deterministic Detection** - No heuristics, query actual hardware IDs and configuration
2. **Kernel-Direct** - All data from sysfs and netlink, not third-party tools
3. **Privacy First** - DNS leak detection without root privileges
4. **Separation of Concerns** - Data collection separate from display
5. **Modern Python** - Uses Python 3.12+ features

### File Structure

```
netcheck/
├── netcheck.py              # Main entry point
├── orchestrator.py          # Coordination module
├── display.py               # Table output formatting
├── export.py                # JSON/CSV export
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
└── utils/                   # Utilities
    └── system.py            # Command execution + IP validation
```

## Development

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-mock pytest-cov

# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html
```

### Code Quality

```bash
# Type checking
mypy netcheck.py orchestrator.py network/ utils/

# Code formatting
black --line-length 100 .

# Import sorting
isort .
```

## Security & Privacy

### Privacy Focused

- **Local operation** - All detection happens on your machine
- **No telemetry** - No data sent anywhere (except ipinfo.io for external IP)
- **No tracking** - No analytics or reporting
- **Open source** - Audit the code yourself

### No Data Collection

The only external service used is ipinfo.io to determine your public IP address and ISP. This is optional - the tool works without it.

## Known Limitations

- External IP info requires internet connectivity
- DNS detection requires systemd-resolved
- Requires modern Linux (kernel 6.12+, hardware 2015+)
- Shows only global scope IPv6 addresses

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
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
