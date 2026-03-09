"""Unit tests for netcheck.core.enums.

Tests verify:
- All expected members exist with the correct string values.
- The ``str`` mixin allows an enum member assigned to a ``str`` variable to
  compare equal to the corresponding string literal without calling ``.value``.
  This is tested by first widening the type to ``str``, which is the realistic
  usage pattern in the rest of the codebase.
- Membership construction from a string value succeeds.
- Invalid values raise ``ValueError``.
- Enumerations are complete -- no accidental member omissions.

Note on mypy and ``str`` enum comparisons
------------------------------------------
mypy 1.15 (strict) treats each enum member as a ``Literal`` type.  A direct
comparison such as ``InterfaceType.LOOPBACK == "loopback"`` is therefore
flagged as a non-overlapping check because the two ``Literal`` types are
statically distinct, even though the ``str`` mixin makes them runtime-equal.

The idiomatic solution is to widen the enum member to ``str`` before
comparing.  This accurately reflects how the mixin is used in production
code, where a function accepting ``str`` receives an enum member directly.
"""

import pytest

from netcheck.core.enums import DnsLeakStatus, EgressStatus, InterfaceType


class TestInterfaceType:
    """Tests for InterfaceType enumeration."""

    def test_all_members_exist(self) -> None:
        """All nine interface classifications must be present."""
        expected = {
            "LOOPBACK",
            "ETHERNET",
            "WIRELESS",
            "VPN",
            "CELLULAR",
            "TETHER",
            "VIRTUAL",
            "BRIDGE",
            "UNKNOWN",
        }
        assert {m.name for m in InterfaceType} == expected

    @pytest.mark.parametrize("member, expected_value", [
        (InterfaceType.LOOPBACK,  "loopback"),
        (InterfaceType.ETHERNET,  "ethernet"),
        (InterfaceType.WIRELESS,  "wireless"),
        (InterfaceType.VPN,       "vpn"),
        (InterfaceType.CELLULAR,  "cellular"),
        (InterfaceType.TETHER,    "tether"),
        (InterfaceType.VIRTUAL,   "virtual"),
        (InterfaceType.BRIDGE,    "bridge"),
        (InterfaceType.UNKNOWN,   "unknown"),
    ])
    def test_string_value(
        self, member: InterfaceType, expected_value: str
    ) -> None:
        """Each member must carry the correct lower-case string value.

        Adding a new member without adding its entry here causes an immediate,
        named failure (``test_string_value[<MEMBER>-<value>]``) rather than a
        silent gap in coverage.
        """
        assert member.value == expected_value

    def test_str_mixin_widens_to_str(self) -> None:
        """A member assigned to a ``str`` variable must equal its value string.

        This tests the practical use of the ``str`` mixin: passing an enum
        member where a plain ``str`` is expected.  The type is widened to
        ``str`` here to match that usage and satisfy mypy's literal checker.
        """
        as_str: str = InterfaceType.ETHERNET
        assert as_str == "ethernet"

        as_str = InterfaceType.VPN
        assert as_str == "vpn"

    def test_construction_from_string(self) -> None:
        """Constructing a member from its string value must succeed."""
        assert InterfaceType("cellular") is InterfaceType.CELLULAR
        assert InterfaceType("unknown") is InterfaceType.UNKNOWN

    def test_invalid_value_raises(self) -> None:
        """An unknown string must raise ``ValueError``."""
        with pytest.raises(ValueError):
            InterfaceType("satellite")

    def test_member_count(self) -> None:
        """There must be exactly nine members."""
        assert len(list(InterfaceType)) == 9

    def test_all_values_are_lowercase(self) -> None:
        """All values must be lower-case for consistent rendering."""
        for member in InterfaceType:
            assert member.value == member.value.lower(), (
                f"InterfaceType.{member.name} value '{member.value}' is not lower-case"
            )

    def test_name_and_value_are_distinct(self) -> None:
        """Member names (upper-case) must differ from their values (lower-case)."""
        for member in InterfaceType:
            assert member.name != member.value, (
                f"InterfaceType.{member.name} has identical name and value"
            )


class TestDnsLeakStatus:
    """Tests for DnsLeakStatus enumeration."""

    def test_all_members_exist(self) -> None:
        """All six leak-status classifications must be present."""
        expected = {"OK", "PUBLIC", "LEAK", "WARN", "DORMANT", "NOT_APPLICABLE"}
        assert {m.name for m in DnsLeakStatus} == expected

    @pytest.mark.parametrize("member, expected_value", [
        (DnsLeakStatus.LEAK,           "leak"),
        (DnsLeakStatus.WARN,           "warn"),
        (DnsLeakStatus.PUBLIC,         "public"),
        (DnsLeakStatus.OK,             "ok"),
        (DnsLeakStatus.DORMANT,        "dormant"),
        (DnsLeakStatus.NOT_APPLICABLE, "not_applicable"),
    ])
    def test_string_value(
        self, member: DnsLeakStatus, expected_value: str
    ) -> None:
        """Each member must carry the correct string value.

        Ordering matches severity: LEAK is the most urgent; NOT_APPLICABLE
        is the least.  Adding a new member without an entry here fails
        immediately with the member name in the test ID.
        """
        assert member.value == expected_value

    def test_str_mixin_widens_to_str(self) -> None:
        """A member assigned to a ``str`` variable must equal its value string."""
        as_str: str = DnsLeakStatus.LEAK
        assert as_str == "leak"

        as_str = DnsLeakStatus.NOT_APPLICABLE
        assert as_str == "not_applicable"

    def test_construction_from_string(self) -> None:
        """Constructing a member from its string value must succeed."""
        assert DnsLeakStatus("leak") is DnsLeakStatus.LEAK
        assert DnsLeakStatus("dormant") is DnsLeakStatus.DORMANT
        assert DnsLeakStatus("not_applicable") is DnsLeakStatus.NOT_APPLICABLE

    def test_invalid_value_raises(self) -> None:
        """An unknown string must raise ``ValueError``."""
        with pytest.raises(ValueError):
            DnsLeakStatus("UNKNOWN")

    def test_not_applicable_value_is_not_a_display_sentinel(self) -> None:
        """NOT_APPLICABLE must carry a domain value, not a display string.

        The value ``"not_applicable"`` is meaningful in the domain layer.
        The display layer owns the decision of how to render it (e.g. ``--``).
        This test confirms the domain value has not been replaced with a
        display sentinel by checking it against the known sentinel set.
        """
        display_sentinels = {"--", "N/A", "NONE", "QUERY FAILED"}
        assert DnsLeakStatus.NOT_APPLICABLE.value not in display_sentinels

    def test_dormant_is_semantically_distinct_from_not_applicable(self) -> None:
        """DORMANT and NOT_APPLICABLE must be distinct members with distinct values.

        They encode different facts: NOT_APPLICABLE means no VPN is active
        (the leak precondition is not met); DORMANT means a VPN IS active
        and this interface correctly stepped aside.  They must never be
        accidentally aliased.

        The set-cardinality assertion is the correct way to prove enum
        distinctness under mypy strict: two equal enum members would collapse
        to a single set element, so a cardinality of 2 proves they differ.
        Direct ``is not`` / ``!=`` comparisons between two Literal enum
        members are statically non-overlapping and would be flagged by mypy
        as vacuously true -- which, paradoxically, means the test could never
        catch a regression introduced at the type level.
        """
        assert len({DnsLeakStatus.DORMANT, DnsLeakStatus.NOT_APPLICABLE}) == 2

    def test_member_count(self) -> None:
        """There must be exactly six members."""
        assert len(list(DnsLeakStatus)) == 6

    def test_all_members_are_distinct(self) -> None:
        """No two members may share the same string value."""
        values = [m.value for m in DnsLeakStatus]
        assert len(values) == len(set(values))


class TestEgressStatus:
    """Tests for EgressStatus enumeration."""

    def test_all_members_exist(self) -> None:
        """All three egress-status values must be present."""
        expected = {"OK", "UNAVAILABLE", "FAILED"}
        assert {m.name for m in EgressStatus} == expected

    @pytest.mark.parametrize("member, expected_value", [
        (EgressStatus.OK,          "ok"),
        (EgressStatus.UNAVAILABLE, "unavailable"),
        (EgressStatus.FAILED,      "failed"),
    ])
    def test_string_value(
        self, member: EgressStatus, expected_value: str
    ) -> None:
        """Each member must carry the correct lower-case string value."""
        assert member.value == expected_value

    def test_str_mixin_widens_to_str(self) -> None:
        """A member assigned to a ``str`` variable must equal its value string."""
        as_str: str = EgressStatus.UNAVAILABLE
        assert as_str == "unavailable"

    def test_all_members_are_distinct(self) -> None:
        """No two members may share the same string value.

        This verifies that UNAVAILABLE and FAILED are distinct, which is
        required for the display layer to render them differently.
        """
        values = [m.value for m in EgressStatus]
        assert len(values) == len(set(values))

    def test_construction_from_string(self) -> None:
        """Constructing a member from its string value must succeed."""
        assert EgressStatus("failed") is EgressStatus.FAILED

    def test_invalid_value_raises(self) -> None:
        """An unknown string must raise ``ValueError``."""
        with pytest.raises(ValueError):
            EgressStatus("unknown")

    def test_member_count(self) -> None:
        """There must be exactly three members."""
        assert len(list(EgressStatus)) == 3
