"""Command-line entry point for netcheck.

Usage::

    python -m netcheck              # display color table on stdout
    python -m netcheck --export json            # JSON to stdout
    python -m netcheck --export json -o report.json  # JSON to file
    python -m netcheck --version    # print version and exit
    python -m netcheck -v           # verbose logging to stderr

Exit codes
----------
0   Success.
1   General error (missing required commands, no interfaces found, I/O
    failure, etc.).

Composition root
----------------
``main()`` is the composition root for the tool.  It is the one place in the
codebase where concrete implementations (``SystemCommandRunner``,
``SystemSysfsReader``, ``SystemHttpClient``) are instantiated directly rather
than received as Protocol arguments.  This is the standard composition-root
pattern and is exempt from the Protocol injection discipline described in
ADR-001 and CONTRIBUTING.md Rule 3.  Tests for ``main()`` use
``pytest.monkeypatch`` (not ``unittest.mock``) and are the only approved use
of attribute replacement in the test suite.
"""

import argparse
import logging
import sys
from pathlib import Path

from netcheck.config import RETRY_ATTEMPTS, RETRY_BACKOFF_FACTOR, VERSION
from netcheck.orchestrator import collect_network_data
from netcheck.output import format_json, format_table
from netcheck.preflight import check_required_commands, format_missing_commands
from netcheck.utils.command import SystemCommandRunner
from netcheck.utils.http import SystemHttpClient
from netcheck.utils.sysfs import SystemSysfsReader

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed namespace with attributes:
            ``export``   -- ``"json"`` or ``None``.
            ``output``   -- ``Path`` or ``None``.
            ``verbose``  -- ``bool``.
    """
    parser = argparse.ArgumentParser(
        prog="netcheck",
        description="Network interface analysis tool for GNU/Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  python -m netcheck
  python -m netcheck --export json
  python -m netcheck --export json -o report.json
  python -m netcheck -v
""",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    parser.add_argument(
        "--export",
        choices=["json"],
        metavar="FORMAT",
        help="export format (currently only 'json')",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="PATH",
        help="write export output to PATH instead of stdout (requires --export)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable debug logging to stderr",
    )
    return parser.parse_args()


def main() -> int:
    """Run netcheck and return an exit code.

    Execution order:
    1.  Parse command-line arguments.
    2.  Configure logging (if ``--verbose``).
    3.  Verify all required system commands are available (pre-flight check).
        Exit 1 with an actionable message if any are missing.
    4.  Collect network data.
    5.  Write output (table or JSON).

    Returns:
        0 on success, 1 on error.
    """
    args = parse_args()

    if args.verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            stream=sys.stderr,
            format="%(levelname)-8s %(name)s.%(funcName)s: %(message)s",
        )
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logger.debug("netcheck %s", VERSION)

    missing = check_required_commands()
    if missing:
        print(format_missing_commands(missing), file=sys.stderr)
        return 1

    runner = SystemCommandRunner()
    reader = SystemSysfsReader()
    client = SystemHttpClient(attempts=RETRY_ATTEMPTS, backoff=RETRY_BACKOFF_FACTOR)

    interfaces = collect_network_data(runner, reader, client)
    if not interfaces:
        print("netcheck: no network interfaces found", file=sys.stderr)
        return 1

    if args.export == "json":
        json_output = format_json(interfaces)
        if args.output:
            try:
                args.output.write_text(json_output, encoding="utf-8")
            except OSError as exc:
                print(f"netcheck: cannot write to {args.output}: {exc}", file=sys.stderr)
                return 1
        else:
            print(json_output)
    else:
        format_table(interfaces)

    return 0


if __name__ == "__main__":
    sys.exit(main())
