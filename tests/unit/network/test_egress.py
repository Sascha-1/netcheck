"""Unit tests for netcheck.network.egress.

All HTTP calls use FakeHttpClient and FakeHttpResponse.
No network access occurs.

Test groups
-----------
TestGetEgressInfo         -- public function: success and failure paths.
TestValidateIpv4Response  -- private helper: field validation.
"""

from netcheck.config import IPINFO_IPV6_URL, IPINFO_URL
from netcheck.core.enums import EgressStatus
from netcheck.network.egress import _validate_ipv4_response, get_egress_info
from tests.fakes import FakeHttpClient, FakeHttpResponse

_IPV4_OK = FakeHttpResponse(
    {"ip": "203.0.113.45", "org": "AS3320 Deutsche Telekom AG", "country": "DE"}
)
_IPV6_OK = FakeHttpResponse({"ip": "2001:db8::1"})


# ---------------------------------------------------------------------------
# TestGetEgressInfo
# ---------------------------------------------------------------------------


class TestGetEgressInfo:
    """Tests for get_egress_info."""

    def test_successful_query_returns_ok_status(self) -> None:
        """A successful IPv4 query must return EgressStatus.OK."""
        client = FakeHttpClient({IPINFO_URL: _IPV4_OK, IPINFO_IPV6_URL: None})
        info = get_egress_info(client)
        assert info.status == EgressStatus.OK

    def test_external_ip_populated(self) -> None:
        """external_ip must be populated from the IPv4 response."""
        client = FakeHttpClient({IPINFO_URL: _IPV4_OK, IPINFO_IPV6_URL: None})
        info = get_egress_info(client)
        assert info.external_ip == "203.0.113.45"

    def test_isp_populated_with_raw_value(self) -> None:
        """isp must contain the raw org value including the AS number."""
        client = FakeHttpClient({IPINFO_URL: _IPV4_OK, IPINFO_IPV6_URL: None})
        info = get_egress_info(client)
        assert info.isp == "AS3320 Deutsche Telekom AG"

    def test_country_populated(self) -> None:
        """country must be populated from the IPv4 response."""
        client = FakeHttpClient({IPINFO_URL: _IPV4_OK, IPINFO_IPV6_URL: None})
        info = get_egress_info(client)
        assert info.country == "DE"

    def test_ipv6_populated_when_available(self) -> None:
        """external_ipv6 must be populated when the IPv6 query succeeds."""
        client = FakeHttpClient({IPINFO_URL: _IPV4_OK, IPINFO_IPV6_URL: _IPV6_OK})
        info = get_egress_info(client)
        assert info.external_ipv6 == "2001:db8::1"

    def test_ipv6_none_when_query_fails(self) -> None:
        """external_ipv6 must be None when the IPv6 query fails."""
        client = FakeHttpClient({IPINFO_URL: _IPV4_OK, IPINFO_IPV6_URL: None})
        info = get_egress_info(client)
        assert info.external_ipv6 is None

    def test_ipv4_failure_returns_failed_status(self) -> None:
        """IPv4 query failure must return EgressStatus.FAILED."""
        client = FakeHttpClient({IPINFO_URL: None, IPINFO_IPV6_URL: None})
        info = get_egress_info(client)
        assert info.status == EgressStatus.FAILED

    def test_ipv4_failure_all_fields_none(self) -> None:
        """On IPv4 failure all data fields must be None."""
        client = FakeHttpClient({IPINFO_URL: None, IPINFO_IPV6_URL: None})
        info = get_egress_info(client)
        assert info.external_ip is None
        assert info.isp is None
        assert info.country is None

    def test_missing_required_field_returns_failed(self) -> None:
        """A response missing a required field must return EgressStatus.FAILED."""
        incomplete = FakeHttpResponse({"ip": "1.2.3.4"})  # missing org, country
        client = FakeHttpClient({IPINFO_URL: incomplete, IPINFO_IPV6_URL: None})
        info = get_egress_info(client)
        assert info.status == EgressStatus.FAILED

    def test_ipv4_queried_before_ipv6(self) -> None:
        """The IPv4 URL must be queried first."""
        client = FakeHttpClient({IPINFO_URL: _IPV4_OK, IPINFO_IPV6_URL: _IPV6_OK})
        get_egress_info(client)
        assert client.calls[0][0] == IPINFO_URL

    def test_ipv6_not_queried_on_ipv4_failure(self) -> None:
        """When IPv4 fails the IPv6 endpoint must not be queried."""
        client = FakeHttpClient({IPINFO_URL: None, IPINFO_IPV6_URL: _IPV6_OK})
        get_egress_info(client)
        queried_urls = [url for url, _ in client.calls]
        assert IPINFO_IPV6_URL not in queried_urls

    def test_ipv6_empty_string_treated_as_none(self) -> None:
        """An empty string for 'ip' in the IPv6 response must result in None."""
        empty_v6 = FakeHttpResponse({"ip": ""})
        client = FakeHttpClient({IPINFO_URL: _IPV4_OK, IPINFO_IPV6_URL: empty_v6})
        info = get_egress_info(client)
        assert info.external_ipv6 is None

    def test_ipv6_missing_ip_field_treated_as_none(self) -> None:
        """A IPv6 response without an 'ip' key must result in external_ipv6=None."""
        no_ip = FakeHttpResponse({"org": "AS1 Test"})
        client = FakeHttpClient({IPINFO_URL: _IPV4_OK, IPINFO_IPV6_URL: no_ip})
        info = get_egress_info(client)
        assert info.external_ipv6 is None


# ---------------------------------------------------------------------------
# TestValidateIpv4Response
# ---------------------------------------------------------------------------


class TestValidateIpv4Response:
    """Tests for _validate_ipv4_response."""

    def test_all_fields_present_returns_true(self) -> None:
        """A complete, valid response dict must return True."""
        data: dict[str, object] = {
            "ip": "203.0.113.45",
            "org": "AS3320 Deutsche Telekom AG",
            "country": "DE",
        }
        assert _validate_ipv4_response(data) is True

    def test_missing_ip_returns_false(self) -> None:
        """Missing 'ip' field must return False."""
        data: dict[str, object] = {"org": "AS3320 DT", "country": "DE"}
        assert _validate_ipv4_response(data) is False

    def test_missing_org_returns_false(self) -> None:
        """Missing 'org' field must return False."""
        data: dict[str, object] = {"ip": "1.2.3.4", "country": "DE"}
        assert _validate_ipv4_response(data) is False

    def test_missing_country_returns_false(self) -> None:
        """Missing 'country' field must return False."""
        data: dict[str, object] = {"ip": "1.2.3.4", "org": "AS1 Test"}
        assert _validate_ipv4_response(data) is False

    def test_empty_ip_string_returns_false(self) -> None:
        """An empty string for 'ip' must return False."""
        data: dict[str, object] = {"ip": "", "org": "AS1 Test", "country": "DE"}
        assert _validate_ipv4_response(data) is False

    def test_non_string_ip_returns_false(self) -> None:
        """A non-string 'ip' field must return False."""
        data: dict[str, object] = {"ip": 12345, "org": "AS1 Test", "country": "DE"}
        assert _validate_ipv4_response(data) is False

    def test_none_ip_returns_false(self) -> None:
        """A None value for 'ip' must return False."""
        data: dict[str, object] = {"ip": None, "org": "AS1 Test", "country": "DE"}
        assert _validate_ipv4_response(data) is False

    def test_empty_dict_returns_false(self) -> None:
        """An empty dict must return False."""
        assert _validate_ipv4_response({}) is False

    def test_extra_fields_tolerated(self) -> None:
        """Extra fields beyond the required three must not affect the result."""
        data: dict[str, object] = {
            "ip": "1.2.3.4",
            "org": "AS1 Test",
            "country": "DE",
            "city": "Berlin",
        }
        assert _validate_ipv4_response(data) is True
