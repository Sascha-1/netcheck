.PHONY: help mypy pylint pytest pytest-integration encoding check \
        clean install uninstall run logs all

SHELL := /bin/bash

PYTHON_VERSION := $(shell python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
$(if $(PYTHON_VERSION),,$(error Could not determine Python version. Is python3 installed?))
INSTALL_DIR    := $(HOME)/.local/bin
SITE_PACKAGES  := $(HOME)/.local/lib/python$(PYTHON_VERSION)/site-packages
PTH_FILE       := $(SITE_PACKAGES)/netcheck.pth
SCRIPT_SRC     := bin/netcheck
SCRIPT_NAME    := netcheck

help:
	@echo "Available targets:"
	@echo "  make mypy               - Run mypy (strict)"
	@echo "  make pylint             - Run pylint (10.0 required)"
	@echo "  make pytest             - Run pytest unit tests with coverage"
	@echo "  make pytest-integration - Run pytest integration tests (requires real Linux hardware)"
	@echo "  make encoding           - Check all source files are ASCII-only"
	@echo "  make check              - Run all checks (mypy + pylint + encoding + pytest + pytest-integration)"
	@echo "  make clean              - Remove cache and build artefacts"
	@echo "  make install            - Install netcheck to ~/.local/bin (no sudo, no pip)"
	@echo "  make uninstall          - Remove netcheck from ~/.local/bin"
	@echo "  make run                - Run from source without installing (ARGS=... optional)"
	@echo "  make logs               - Capture VPN-off then VPN-on snapshots to logs/"
	@echo "  make all                - Run make check then make logs"

mypy:
	@echo "Running mypy..."
	@mypy
	@echo "OK: mypy passed"

pylint:
	@echo "Running pylint..."
	@pylint src/netcheck/ tests/
	@echo "OK: pylint passed"

pytest:
	@echo "Running pytest..."
	@pytest
	@echo "OK: pytest passed"

pytest-integration:
	@echo "Running pytest (integration)..."
	@pytest -m integration -v
	@echo "OK: pytest integration passed"

encoding:
	@echo "Checking source encoding (ASCII only)..."
	@if grep -rP --include='*.py' '[^\x00-\x7F]' src/netcheck/ tests/; then \
		echo "ERROR: non-ASCII characters found (see above)"; \
		exit 1; \
	fi
	@echo "OK: all source files are ASCII"

check: mypy pylint encoding pytest pytest-integration
	@echo ""
	@echo "================================================"
	@echo "OK: All checks passed."
	@echo "================================================"

clean:
	rm -rf .pytest_cache .mypy_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

install:
	@mkdir -p $(INSTALL_DIR)
	@mkdir -p $(SITE_PACKAGES)
	@echo "$(CURDIR)/src" > $(PTH_FILE)
	@cp $(SCRIPT_SRC) $(INSTALL_DIR)/$(SCRIPT_NAME)
	@chmod 755 $(INSTALL_DIR)/$(SCRIPT_NAME)
	@echo "Registered: $(PTH_FILE)"
	@echo "Installed:  $(INSTALL_DIR)/$(SCRIPT_NAME)"
	@if ! echo "$$PATH" | grep -q "$(HOME)/.local/bin"; then \
		echo ""; \
		echo "NOTE: ~/.local/bin is not on your PATH in this shell session."; \
		echo "Log out and back in, or run:"; \
		echo "  source ~/.profile"; \
		echo "to make the netcheck command available."; \
	fi

uninstall:
	@rm -f $(INSTALL_DIR)/$(SCRIPT_NAME)
	@rm -f $(PTH_FILE)
	@echo "Removed: $(INSTALL_DIR)/$(SCRIPT_NAME)"
	@echo "Removed: $(PTH_FILE)"

run:
	@PYTHONPATH=src python3 -m netcheck $(ARGS)

logs:
	@mkdir -p logs
	@echo ""
	@echo "Step 1 of 2: Capturing VPN-OFF snapshot."
	@echo "Make sure your VPN is DISCONNECTED, then press Enter to continue."
	@read _confirm
	@echo "  Running (JSON)..."
	@PYTHONPATH=src python3 -m netcheck --export json -v \
		> logs/report_vpn-off.json \
		2> logs/report_vpn-off.log
	@echo "  Running (table)..."
	@PYTHONPATH=src python3 -m netcheck -v \
		> logs/table_vpn-off.txt \
		2> logs/table_vpn-off.log
	@echo "  Written: logs/report_vpn-off.json"
	@echo "  Written: logs/report_vpn-off.log"
	@echo "  Written: logs/table_vpn-off.txt"
	@echo "  Written: logs/table_vpn-off.log"
	@echo ""
	@echo "Step 2 of 2: Capturing VPN-ON snapshot."
	@echo "Connect your VPN now, then press Enter to continue."
	@read _confirm
	@echo "  Running (JSON)..."
	@PYTHONPATH=src python3 -m netcheck --export json -v \
		> logs/report_vpn-on.json \
		2> logs/report_vpn-on.log
	@echo "  Running (table)..."
	@PYTHONPATH=src python3 -m netcheck -v \
		> logs/table_vpn-on.txt \
		2> logs/table_vpn-on.log
	@echo "  Written: logs/report_vpn-on.json"
	@echo "  Written: logs/report_vpn-on.log"
	@echo "  Written: logs/table_vpn-on.txt"
	@echo "  Written: logs/table_vpn-on.log"
	@echo ""
	@echo "Done. Files written to logs/:"
	@echo "  report_vpn-off.json  report_vpn-off.log"
	@echo "  table_vpn-off.txt    table_vpn-off.log"
	@echo "  report_vpn-on.json   report_vpn-on.log"
	@echo "  table_vpn-on.txt     table_vpn-on.log"

all:
	@mkdir -p logs
	@$(MAKE) --no-print-directory check 2>&1 | tee logs/check.log; exit $${PIPESTATUS[0]}
	@echo "  Written: logs/check.log"
	@$(MAKE) --no-print-directory logs
