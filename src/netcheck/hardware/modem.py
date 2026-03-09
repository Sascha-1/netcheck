"""ModemManager integration for cellular modem detection.

Queries the ModemManager daemon via ``mmcli`` to identify which network
interfaces belong to cellular modems, and to retrieve modem state.

Design
------
``get_all_modem_data`` performs all subprocess calls and returns a list of
``ModemRecord`` objects -- one per modem.  The orchestrator calls this once
and distributes the results, avoiding repeated ``mmcli`` invocations.

``ModemRecord`` is the intermediate data structure returned by ``get_all_modem_data``.
Callers outside this module use
the public helpers ``get_modem_interfaces`` and ``build_modem_info``, which
operate on the already-fetched record list.

ModemManager port detection
---------------------------
``mmcli -m <n> -K`` reports ports in two formats depending on version.

Old format (ModemManager < 1.18) -- all ports on one line::

    modem.generic.ports : ttyUSB0 (at), wwp195s0f3u4 (net), cdc-wdm0 (qmi)

New format (ModemManager >= 1.18) -- one port per indexed line::

    modem.generic.ports.length   : 3
    modem.generic.ports.value[1] : cdc-wdm1 (mbim)
    modem.generic.ports.value[2] : ttyUSB0 (at)
    modem.generic.ports.value[3] : wwp195s0f3u4 (net)

Both formats are handled by ``parse_modem_record``.  Only ports annotated
``(net)`` are network interfaces.  This is the authoritative,
injection-safe way to map a modem to its netdev -- it does not rely on
sysfs path prefix matching, which was the root cause of the
misclassification bug in netcheck_2.
"""

import logging
import re
from typing import Final
from dataclasses import dataclass

from netcheck.core.models import ModemInfo
from netcheck.utils.command import CommandRunner

logger = logging.getLogger(__name__)

# Matches a single port entry: "name (type)"
_PORT_PATTERN: Final[re.Pattern[str]] = re.compile(r"(\S+)\s+\((\w+)\)")

# Matches the modem index from mmcli -L output:
# "    /org/freedesktop/ModemManager1/Modem/3 [Vendor] Model"
_MODEM_INDEX_PATTERN: Final[re.Pattern[str]] = re.compile(r"/Modem/(\d+)")


@dataclass(frozen=True)
class ModemRecord:
    """All data extracted from one ``mmcli -m <n> -K`` invocation.

    Internal to this module.  External code uses the public helpers.
    """

    index: str
    interfaces: frozenset[str]  # Only (net) ports
    state: str | None
    state_reason: str | None


def get_all_modem_data(runner: CommandRunner) -> list[ModemRecord]:
    """Query ModemManager and return one record per modem.

    Calls ``mmcli -L`` once to discover modem indices, then
    ``mmcli -m <n> -K`` once per modem.  If ModemManager is absent or
    returns no modems, returns an empty list without raising.

    Args:
        runner: Command runner used for all subprocess calls.

    Returns:
        List of ``ModemRecord`` objects, one per discovered modem.
        Empty if ModemManager is unavailable or no modems are present.
    """
    list_output = runner.run(["mmcli", "-L"])
    if not list_output:
        return []

    indices = parse_modem_indices(list_output)
    if not indices:
        return []

    records = []
    for index in indices:
        kv_output = runner.run(["mmcli", "-m", index, "-K"])
        if kv_output:
            records.append(parse_modem_record(index, kv_output))

    return records


def get_modem_interfaces(records: list[ModemRecord]) -> frozenset[str]:
    """Return all interface names managed by ModemManager.

    Aggregates the ``(net)`` ports from every modem record into a single
    frozenset.  The orchestrator uses this set to classify interfaces as
    ``CELLULAR`` before falling through to other detection rules.

    Args:
        records: Output of ``get_all_modem_data``.

    Returns:
        Frozenset of interface names (e.g. ``frozenset({"wwp195s0f3u4"})``)
        Empty frozenset if no modems are present.
    """
    result: set[str] = set()
    for record in records:
        result.update(record.interfaces)
    return frozenset(result)


def build_modem_info(
    iface_name: str,
    records: list[ModemRecord],
) -> ModemInfo | None:
    """Return a ``ModemInfo`` for the modem that owns ``iface_name``, or ``None``.

    Searches the record list for the modem whose ``(net)`` ports include
    ``iface_name``.  If found, constructs and returns a ``ModemInfo`` with
    state and state_reason populated.  If no modem claims this interface,
    returns ``None``.

    Args:
        iface_name: Network interface name to look up.
        records: Output of ``get_all_modem_data``.

    Returns:
        ``ModemInfo`` if the interface belongs to a known modem, else ``None``.
    """
    for record in records:
        if iface_name in record.interfaces:
            return ModemInfo(
                state=record.state,
                state_reason=record.state_reason,
            )
    return None


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------
def parse_modem_indices(list_output: str) -> list[str]:
    """Extract modem indices from ``mmcli -L`` output.

    Args:
        list_output: Raw stdout from ``mmcli -L``.

    Returns:
        List of index strings (e.g. ``["0", "1"]``).
    """
    indices = []
    for line in list_output.splitlines():
        match = _MODEM_INDEX_PATTERN.search(line)
        if match:
            indices.append(match.group(1))
    return indices


def parse_modem_record(index: str, kv_output: str) -> ModemRecord:
    """Parse ``mmcli -m <n> -K`` output into a ``ModemRecord``.

    Extracts three fields from the key-value output:

    - ``modem.generic.ports`` -- scans for ``name (net)`` entries
    - ``modem.generic.state`` -- current modem state string
    - ``modem.generic.state-failed-reason`` -- reason string when failed

    ``state`` is ``None`` when the ``modem.generic.state`` key is absent
    from the output (possible with older ModemManager versions) or when
    ``kv_output`` is empty.  It is not guaranteed to be populated whenever
    mmcli exits successfully.

    The ``state-failed-reason`` value ``"none"`` is normalised to ``None``
    because it is a ModemManager placeholder, not a meaningful value.

    Args:
        index: Modem index string (e.g. ``"0"``).
        kv_output: Raw stdout from ``mmcli -m <n> -K``.

    Returns:
        Populated ``ModemRecord``.
    """
    net_interfaces: set[str] = set()
    state: str | None = None
    state_reason: str | None = None

    for line in kv_output.splitlines():
        if ":" not in line:
            continue

        key, _, raw_value = line.partition(":")
        key = key.strip()
        value = raw_value.strip()

        # Match both the single-line format ("modem.generic.ports") used by
        # ModemManager as shipped in Debian 11 (Bullseye) and earlier, and the
        # per-line array format ("modem.generic.ports.value[N]") used from
        # Debian 12 (Bookworm) onward (ModemManager >= 1.18).  Both formats
        # use the same port-entry syntax ("name (type)") so _PORT_PATTERN
        # handles both.  The ".length" and ".value[N]" suffixes share the
        # "ports" prefix, so we test for ".value[" to avoid matching the
        # length line.
        is_ports_old = key == "modem.generic.ports"
        is_ports_new = key.startswith("modem.generic.ports.value[")
        if is_ports_old or is_ports_new:
            for port_match in _PORT_PATTERN.finditer(value):
                port_name, port_type = port_match.groups()
                if port_type == "net":
                    net_interfaces.add(port_name)

        elif key == "modem.generic.state":
            state = value if value else None

        elif key == "modem.generic.state-failed-reason":
            # "none" is a ModemManager placeholder meaning no failure reason
            state_reason = None if value in ("none", "") else value

    logger.debug(
        "modem %s: interfaces=%s state=%s state_reason=%s",
        index, net_interfaces, state, state_reason,
    )

    return ModemRecord(
        index=index,
        interfaces=frozenset(net_interfaces),
        state=state,
        state_reason=state_reason,
    )
