"""Comprehensive tests for netcheck.py main entry point and CLI."""

import sys
from pathlib import Path
from unittest.mock import Mock, patch, call
import pytest

from models import InterfaceInfo
from enums import InterfaceType, DnsLeakStatus, DataMarker


class TestArgumentParsing:
    """Test command-line argument parsing."""

    @patch('sys.argv', ['netcheck.py'])
    def test_parse_args_defaults(self) -> None:
        """Test default argument values when no flags provided."""
        from netcheck import parse_arguments
        
        args = parse_arguments()
        
        assert args.verbose is False
        assert args.no_color is False
        assert args.log_file is None
        assert args.export is None
        assert args.output is None

    @patch('sys.argv', ['netcheck.py', '-v'])
    def test_parse_args_verbose_short(self) -> None:
        """Test verbose flag short form."""
        from netcheck import parse_arguments
        
        args = parse_arguments()
        
        assert args.verbose is True

    @patch('sys.argv', ['netcheck.py', '--verbose'])
    def test_parse_args_verbose_long(self) -> None:
        """Test verbose flag long form."""
        from netcheck import parse_arguments
        
        args = parse_arguments()
        
        assert args.verbose is True

    @patch('sys.argv', ['netcheck.py', '--no-color'])
    def test_parse_args_no_color(self) -> None:
        """Test no-color flag."""
        from netcheck import parse_arguments
        
        args = parse_arguments()
        
        assert args.no_color is True

    @patch('sys.argv', ['netcheck.py', '--log-file', '/tmp/test.log'])
    def test_parse_args_log_file(self) -> None:
        """Test log-file argument."""
        from netcheck import parse_arguments
        
        args = parse_arguments()
        
        assert args.log_file == Path('/tmp/test.log')

    @patch('sys.argv', ['netcheck.py', '--export', 'json'])
    def test_parse_args_export_json(self) -> None:
        """Test export json format."""
        from netcheck import parse_arguments
        
        args = parse_arguments()
        
        assert args.export == 'json'

    @patch('sys.argv', ['netcheck.py', '--export', 'csv'])
    def test_parse_args_export_csv(self) -> None:
        """Test export csv format."""
        from netcheck import parse_arguments
        
        args = parse_arguments()
        
        assert args.export == 'csv'

    @patch('sys.argv', ['netcheck.py', '--export', 'json', '--output', '/tmp/output.json'])
    def test_parse_args_export_with_output(self) -> None:
        """Test export with output file."""
        from netcheck import parse_arguments
        
        args = parse_arguments()
        
        assert args.export == 'json'
        assert args.output == Path('/tmp/output.json')

    @patch('sys.argv', ['netcheck.py', '-v', '--no-color', '--log-file', '/var/log/netcheck.log'])
    def test_parse_args_all_flags_combined(self) -> None:
        """Test all command-line flags together."""
        from netcheck import parse_arguments
        
        args = parse_arguments()
        
        assert args.verbose is True
        assert args.no_color is True
        assert args.log_file == Path('/var/log/netcheck.log')

    @patch('sys.argv', ['netcheck.py', '--help'])
    def test_parse_args_help_exits(self) -> None:
        """Test that --help causes exit."""
        from netcheck import parse_arguments
        
        with pytest.raises(SystemExit) as exc_info:
            parse_arguments()
        
        assert exc_info.value.code == 0


class TestMainExecution:
    """Test main execution flow."""

    @patch('netcheck.collect_network_data')
    @patch('netcheck.format_output')
    @patch('netcheck.check_dependencies')
    @patch('netcheck.setup_logging')
    def test_main_success_no_interfaces(
        self,
        mock_setup_logging: Mock,
        mock_check_deps: Mock,
        mock_format: Mock,
        mock_collect: Mock,
    ) -> None:
        """Test main execution with no network interfaces."""
        mock_check_deps.return_value = True
        mock_collect.return_value = []
        
        from netcheck import main
        
        with patch('sys.argv', ['netcheck.py']):
            main()  # Returns None
        
        mock_collect.assert_called_once()
        mock_format.assert_called_once_with([])

    @patch('netcheck.collect_network_data')
    @patch('netcheck.format_output')
    @patch('netcheck.check_dependencies')
    @patch('netcheck.setup_logging')
    def test_main_success_with_interfaces(
        self,
        mock_setup_logging: Mock,
        mock_check_deps: Mock,
        mock_format: Mock,
        mock_collect: Mock,
    ) -> None:
        """Test main execution with network interfaces."""
        mock_check_deps.return_value = True
        
        test_interface = InterfaceInfo(
            name="eth0",
            interface_type=InterfaceType.ETHERNET,
            device="Intel I219-V",
            internal_ipv4="192.168.1.100",
            internal_ipv6=DataMarker.NOT_AVAILABLE,
            dns_servers=["192.168.1.1"],
            current_dns="192.168.1.1",
            dns_leak_status=DnsLeakStatus.NOT_APPLICABLE,
            external_ipv4=DataMarker.NOT_APPLICABLE,
            external_ipv6=DataMarker.NOT_APPLICABLE,
            egress_isp=DataMarker.NOT_APPLICABLE,
            egress_country=DataMarker.NOT_APPLICABLE,
            default_gateway="192.168.1.1",
            metric="100",
            vpn_server_ip=None,
            carries_vpn=False,
        )
        mock_collect.return_value = [test_interface]
        
        from netcheck import main
        
        with patch('sys.argv', ['netcheck.py']):
            main()
        
        mock_collect.assert_called_once()
        mock_format.assert_called_once()

    @patch('netcheck.check_dependencies')
    @patch('netcheck.setup_logging')
    def test_main_dependencies_missing(
        self,
        mock_setup_logging: Mock,
        mock_check_deps: Mock,
    ) -> None:
        """Test main exits when dependencies missing."""
        mock_check_deps.return_value = False
        
        from netcheck import main
        
        with patch('sys.argv', ['netcheck.py']):
            with pytest.raises(SystemExit) as exc_info:
                main()
        
        assert exc_info.value.code == 1

    @patch('netcheck.collect_network_data')
    @patch('netcheck.check_dependencies')
    @patch('netcheck.setup_logging')
    def test_main_export_json_stdout(
        self,
        mock_setup_logging: Mock,
        mock_check_deps: Mock,
        mock_collect: Mock,
    ) -> None:
        """Test JSON export to stdout."""
        mock_check_deps.return_value = True
        mock_collect.return_value = []
        
        from netcheck import main
        
        with patch('sys.argv', ['netcheck.py', '--export', 'json']):
            with patch('netcheck.export_to_json') as mock_export:
                mock_export.return_value = '{"test": "data"}'
                with patch('builtins.print') as mock_print:
                    main()
                
                mock_export.assert_called_once()
                mock_print.assert_called_once()

    @patch('netcheck.collect_network_data')
    @patch('netcheck.check_dependencies')
    @patch('netcheck.setup_logging')
    def test_main_export_csv_stdout(
        self,
        mock_setup_logging: Mock,
        mock_check_deps: Mock,
        mock_collect: Mock,
    ) -> None:
        """Test CSV export to stdout."""
        mock_check_deps.return_value = True
        mock_collect.return_value = []
        
        from netcheck import main
        
        with patch('sys.argv', ['netcheck.py', '--export', 'csv']):
            with patch('netcheck.export_to_csv') as mock_export:
                mock_export.return_value = 'name,type\neth0,ethernet\n'
                with patch('builtins.print') as mock_print:
                    main()
                
                mock_export.assert_called_once()
                mock_print.assert_called_once()

    @patch('netcheck.collect_network_data')
    @patch('netcheck.check_dependencies')
    @patch('netcheck.setup_logging')
    def test_main_export_json_to_file(
        self,
        mock_setup_logging: Mock,
        mock_check_deps: Mock,
        mock_collect: Mock,
        tmp_path: Path,
    ) -> None:
        """Test JSON export to file."""
        mock_check_deps.return_value = True
        mock_collect.return_value = []
        
        output_file = tmp_path / "test.json"
        
        from netcheck import main
        
        with patch('sys.argv', ['netcheck.py', '--export', 'json', '--output', str(output_file)]):
            with patch('netcheck.save_json') as mock_save:
                main()
                
                mock_save.assert_called_once_with([], str(output_file))

    @patch('netcheck.setup_logging')
    def test_main_output_without_export_fails(
        self,
        mock_setup_logging: Mock,
    ) -> None:
        """Test that --output requires --export."""
        from netcheck import main
        
        with patch('sys.argv', ['netcheck.py', '--output', '/tmp/test.json']):
            with pytest.raises(SystemExit) as exc_info:
                main()
        
        assert exc_info.value.code == 1


class TestLoggingSetup:
    """Test logging configuration."""

    @patch('netcheck.collect_network_data')
    @patch('netcheck.format_output')
    @patch('netcheck.check_dependencies')
    @patch('netcheck.setup_logging')
    def test_setup_logging_called_verbose(
        self,
        mock_setup: Mock,
        mock_check_deps: Mock,
        mock_format: Mock,
        mock_collect: Mock,
    ) -> None:
        """Test logging setup with verbose flag."""
        mock_check_deps.return_value = True
        mock_collect.return_value = []
        
        from netcheck import main
        
        with patch('sys.argv', ['netcheck.py', '-v']):
            main()
        
        mock_setup.assert_called_once()
        call_kwargs = mock_setup.call_args.kwargs
        assert call_kwargs['verbose'] is True

    @patch('netcheck.collect_network_data')
    @patch('netcheck.format_output')
    @patch('netcheck.check_dependencies')
    @patch('netcheck.setup_logging')
    def test_setup_logging_called_no_color(
        self,
        mock_setup: Mock,
        mock_check_deps: Mock,
        mock_format: Mock,
        mock_collect: Mock,
    ) -> None:
        """Test logging setup with no-color flag."""
        mock_check_deps.return_value = True
        mock_collect.return_value = []
        
        from netcheck import main
        
        with patch('sys.argv', ['netcheck.py', '--no-color']):
            main()
        
        mock_setup.assert_called_once()
        call_kwargs = mock_setup.call_args.kwargs
        assert call_kwargs['use_colors'] is False


class TestIntegration:
    """Integration tests for complete workflows."""

    @patch('netcheck.collect_network_data')
    @patch('netcheck.format_output')
    @patch('netcheck.check_dependencies')
    @patch('netcheck.setup_logging')
    def test_complete_workflow_with_vpn(
        self,
        mock_setup_logging: Mock,
        mock_check_deps: Mock,
        mock_format: Mock,
        mock_collect: Mock,
    ) -> None:
        """Test complete workflow with VPN active."""
        mock_check_deps.return_value = True
        
        eth0 = InterfaceInfo(
            name="eth0",
            interface_type=InterfaceType.ETHERNET,
            device="Intel I219-V",
            internal_ipv4="192.168.1.100",
            internal_ipv6=DataMarker.NOT_AVAILABLE,
            dns_servers=[],
            current_dns=None,
            dns_leak_status=DnsLeakStatus.NOT_APPLICABLE,
            external_ipv4=DataMarker.NOT_APPLICABLE,
            external_ipv6=DataMarker.NOT_APPLICABLE,
            egress_isp=DataMarker.NOT_APPLICABLE,
            egress_country=DataMarker.NOT_APPLICABLE,
            default_gateway="192.168.1.1",
            metric="100",
            vpn_server_ip=None,
            carries_vpn=False,
        )
        
        tun0 = InterfaceInfo(
            name="tun0",
            interface_type=InterfaceType.VPN,
            device=DataMarker.NOT_AVAILABLE,
            internal_ipv4="10.2.0.2",
            internal_ipv6="2a07:b944::2:2",
            dns_servers=["10.2.0.1"],
            current_dns="10.2.0.1",
            dns_leak_status=DnsLeakStatus.OK,
            external_ipv4="159.26.108.89",
            external_ipv6="2001:db8::1",
            egress_isp="Proton AG",
            egress_country="SE",
            default_gateway=DataMarker.NONE_VALUE,
            metric=DataMarker.NONE_VALUE,
            vpn_server_ip="10.2.0.1",
            carries_vpn=False,
        )
        
        mock_collect.return_value = [eth0, tun0]
        
        from netcheck import main
        
        with patch('sys.argv', ['netcheck.py']):
            main()
        
        mock_format.assert_called_once_with([eth0, tun0])
