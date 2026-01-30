"""
Tests for network.egress module.

Tests external IP and ISP information retrieval from ipinfo.io.
"""

from typing import Any, Dict, List, Optional, Generator
from pathlib import Path
from unittest.mock import MagicMock
from _pytest.logging import LogCaptureFixture
from _pytest.capture import CaptureFixture
from _pytest.config import Config
from _pytest.monkeypatch import MonkeyPatch


import pytest
from unittest.mock import patch, Mock
import requests
from network.egress import get_egress_info
from models import EgressInfo


class TestGetEgressInfo:
    """Test egress information retrieval."""
    
    @patch('network.egress.requests.get')
    def test_successful_query(self, mock_get: Any) -> None:

        """Test successful API query for both IPv4 and IPv6."""
        # Mock IPv4 response
        mock_ipv4 = Mock()
        mock_ipv4.status_code = 200
        mock_ipv4.json.return_value = {
            "ip": "1.2.3.4",
            "org": "AS12345 Example ISP",
            "country": "US"
        }
        
        # Mock IPv6 response
        mock_ipv6 = Mock()
        mock_ipv6.status_code = 200
        mock_ipv6.json.return_value = {
            "ip": "2001:db8::1",
            "org": "AS12345 Example ISP",
            "country": "US"
        }
        
        mock_get.side_effect = [mock_ipv4, mock_ipv6]
        
        result = get_egress_info()
        
        assert result.external_ip == "1.2.3.4"
        assert result.external_ipv6 == "2001:db8::1"
        assert result.isp == "AS12345 Example ISP"
        assert result.country == "US"
        assert mock_get.call_count == 2
    
    @patch('network.egress.requests.get')
    def test_vpn_egress(self, mock_get: Any) -> None:

        """Test VPN egress information with IPv6."""
        mock_ipv4 = Mock()
        mock_ipv4.status_code = 200
        mock_ipv4.json.return_value = {
            "ip": "159.26.108.89",
            "org": "AS12345 Proton AG",
            "country": "SE"
        }
        
        mock_ipv6 = Mock()
        mock_ipv6.status_code = 200
        mock_ipv6.json.return_value = {
            "ip": "2a07:b944::100",
            "org": "AS12345 Proton AG",
            "country": "SE"
        }
        
        mock_get.side_effect = [mock_ipv4, mock_ipv6]
        
        result = get_egress_info()
        
        assert result.external_ip == "159.26.108.89"
        assert result.external_ipv6 == "2a07:b944::100"
        assert result.isp == "AS12345 Proton AG"
        assert result.country == "SE"
    
    @patch('network.egress.requests.get')
    def test_http_error_status(self, mock_get: Any) -> None:

        """Test handling of HTTP error status."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response
        
        result = get_egress_info()
        
        assert result.external_ip == "ERR"
        assert result.external_ipv6 == "--"  # IPv6 not queried if IPv4 fails
        assert result.isp == "ERR"
        assert result.country == "ERR"
    
    @patch('network.egress.requests.get')
    def test_timeout(self, mock_get: Any) -> None:

        """Test handling of request timeout."""
        mock_get.side_effect = requests.exceptions.Timeout()
        
        result = get_egress_info()
        
        assert result.external_ip == "ERR"
        assert result.external_ipv6 == "--"  # IPv6 not queried if IPv4 fails
        assert result.isp == "ERR"
        assert result.country == "ERR"
    
    @patch('network.egress.requests.get')
    def test_connection_error(self, mock_get: Any) -> None:

        """Test handling of connection error."""
        mock_get.side_effect = requests.exceptions.ConnectionError()
        
        result = get_egress_info()
        
        assert result.external_ip == "ERR"
        assert result.external_ipv6 == "--"  # IPv6 not queried if IPv4 fails
        assert result.isp == "ERR"
        assert result.country == "ERR"
    
    @patch('network.egress.requests.get')
    def test_request_exception(self, mock_get: Any) -> None:

        """Test handling of general request exception."""
        mock_get.side_effect = requests.exceptions.RequestException("Network error")
        
        result = get_egress_info()
        
        assert result.external_ip == "ERR"
        assert result.external_ipv6 == "--"  # IPv6 not queried if IPv4 fails
        assert result.isp == "ERR"
        assert result.country == "ERR"
    
    @patch('network.egress.requests.get')
    def test_unexpected_exception(self, mock_get: Any) -> None:

        """Test handling of unexpected exception."""
        mock_get.side_effect = Exception("Unexpected error")
        
        result = get_egress_info()
        
        assert result.external_ip == "ERR"
        assert result.external_ipv6 == "--"  # IPv6 not queried if IPv4 fails
        assert result.isp == "ERR"
        assert result.country == "ERR"
    
    @patch('network.egress.requests.get')
    def test_missing_fields(self, mock_get: Any) -> None:

        """Test handling of missing fields in response."""
        mock_ipv4 = Mock()
        mock_ipv4.status_code = 200
        mock_ipv4.json.return_value = {
            "ip": "1.2.3.4"
            # Missing org and country
        }
        
        mock_ipv6 = Mock()
        mock_ipv6.status_code = 200
        mock_ipv6.json.return_value = {
            "ip": "2001:db8::1"
        }
        
        mock_get.side_effect = [mock_ipv4, mock_ipv6]
        
        result = get_egress_info()
        
        assert result.external_ip == "1.2.3.4"
        assert result.external_ipv6 == "2001:db8::1"
        assert result.isp == "ERR"
        assert result.country == "ERR"
    
    @patch('network.egress.requests.get')
    def test_empty_response(self, mock_get: Any) -> None:

        """Test handling of empty response."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_get.return_value = mock_response
        
        result = get_egress_info()
        
        assert result.external_ip == "ERR"
        assert result.external_ipv6 == "--"  # IPv6 query also got empty, so it's "--" (unavailable)
        assert result.isp == "ERR"
        assert result.country == "ERR"
    
    @patch('network.egress.requests.get')
    def test_json_decode_error(self, mock_get: Any) -> None:

        """Test handling of JSON decode error."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_get.return_value = mock_response
        
        result = get_egress_info()
        
        assert result.external_ip == "ERR"
        assert result.external_ipv6 == "--"  # IPv6 query also failed JSON parsing, so it's "--" (unavailable)
        assert result.isp == "ERR"
        assert result.country == "ERR"
    
    @patch('network.egress.requests.get')
    def test_no_ipv6_available(self, mock_get: Any) -> None:

        """Test handling when IPv6 is not available."""
        mock_ipv4 = Mock()
        mock_ipv4.status_code = 200
        mock_ipv4.json.return_value = {
            "ip": "1.2.3.4",
            "org": "AS12345 Example ISP",
            "country": "US"
        }
        
        # IPv6 fails (no connectivity)
        mock_get.side_effect = [mock_ipv4, requests.exceptions.ConnectionError()]
        
        result = get_egress_info()
        
        assert result.external_ip == "1.2.3.4"
        assert result.external_ipv6 == "--"  # Not available
        assert result.isp == "AS12345 Example ISP"
        assert result.country == "US"
    
    @patch('network.egress.requests.get')
    def test_raw_isp_format_preserved(self, mock_get: Any) -> None:

        """Test that raw ISP format with ASN is preserved."""
        mock_ipv4 = Mock()
        mock_ipv4.status_code = 200
        mock_ipv4.json.return_value = {
            "ip": "1.2.3.4",
            "org": "AS12345 Some Very Long ISP Name Corporation",
            "country": "US"
        }
        
        mock_ipv6 = Mock()
        mock_ipv6.status_code = 200
        mock_ipv6.json.return_value = {
            "ip": "2001:db8::1",
            "org": "AS12345 Some Very Long ISP Name Corporation",
            "country": "US"
        }
        
        mock_get.side_effect = [mock_ipv4, mock_ipv6]
        
        result = get_egress_info()
        
        # Raw format should be preserved (cleaning happens in display layer)
        assert result.isp == "AS12345 Some Very Long ISP Name Corporation"
    
    @patch('network.egress.requests.get')
    def test_timeout_value_used(self, mock_get: Any) -> None:

        """Test that timeout value from config is used."""
        mock_ipv4 = Mock()
        mock_ipv4.status_code = 200
        mock_ipv4.json.return_value = {
            "ip": "1.2.3.4",
            "org": "AS12345 Example ISP",
            "country": "US"
        }
        
        mock_ipv6 = Mock()
        mock_ipv6.status_code = 200
        mock_ipv6.json.return_value = {
            "ip": "2001:db8::1",
            "org": "AS12345 Example ISP",
            "country": "US"
        }
        
        mock_get.side_effect = [mock_ipv4, mock_ipv6]
        
        get_egress_info()
        
        # Verify timeout parameter was passed (check first call)
        call_args = mock_get.call_args_list[0]
        assert 'timeout' in call_args[1]
        assert call_args[1]['timeout'] > 0


class TestEgressInfoModel:
    """Test EgressInfo model integration."""
    
    @patch('network.egress.requests.get')
    def test_creates_valid_egress_info(self, mock_get: Any) -> None:

        """Test that valid EgressInfo object is created."""
        mock_ipv4 = Mock()
        mock_ipv4.status_code = 200
        mock_ipv4.json.return_value = {
            "ip": "1.2.3.4",
            "org": "AS12345 Example ISP",
            "country": "US"
        }
        
        mock_ipv6 = Mock()
        mock_ipv6.status_code = 200
        mock_ipv6.json.return_value = {
            "ip": "2001:db8::1",
            "org": "AS12345 Example ISP",
            "country": "US"
        }
        
        mock_get.side_effect = [mock_ipv4, mock_ipv6]
        
        result = get_egress_info()
        
        assert isinstance(result, EgressInfo)
        assert hasattr(result, 'external_ip')
        assert hasattr(result, 'external_ipv6')
        assert hasattr(result, 'isp')
        assert hasattr(result, 'country')
    
    @patch('network.egress.requests.get')
    def test_creates_error_egress_info(self, mock_get: Any) -> None:

        """Test that error EgressInfo is created on failure."""
        mock_get.side_effect = requests.exceptions.ConnectionError()
        
        result = get_egress_info()
        
        assert isinstance(result, EgressInfo)
        # When first request fails, IPv4/ISP/country are ERR, but IPv6 is "--" (not queried)
        assert result.external_ip == "ERR"
        assert result.external_ipv6 == "--"
        assert result.isp == "ERR"
        assert result.country == "ERR"
