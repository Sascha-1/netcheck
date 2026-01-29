"""
Export functionality for network analysis data.

Provides JSON and CSV export capabilities for InterfaceInfo data.
Both formats are built-in to Python (no external dependencies).

Why JSON:
    - Perfect for structured/nested data
    - Native Python types
    - Easy to parse programmatically
    - Standard format for APIs/automation

Why CSV:
    - Universal spreadsheet compatibility
    - Human-readable in text editors
    - Easy to import into Excel/Google Sheets
    - Good for tabular analysis

Usage:
    >>> from export import export_to_json, export_to_csv
    >>> interfaces = collect_network_data()
    >>> 
    >>> # Export to JSON
    >>> json_output = export_to_json(interfaces)
    >>> print(json_output)
    >>> 
    >>> # Export to CSV
    >>> csv_output = export_to_csv(interfaces)
    >>> print(csv_output)
"""

import json
import csv
from typing import List, Dict, Any
from io import StringIO
from datetime import datetime

from models import InterfaceInfo


def _interface_to_dict(interface: InterfaceInfo) -> Dict[str, Any]:
    """
    Convert InterfaceInfo to dictionary for serialization.
    
    Args:
        interface: InterfaceInfo object to convert
        
    Returns:
        Dictionary representation of interface data
    """
    return {
        "name": interface.name,
        "interface_type": interface.interface_type,
        "device": interface.device,
        "internal_ipv4": interface.internal_ipv4,
        "internal_ipv6": interface.internal_ipv6,
        "dns_servers": interface.dns_servers,
        "current_dns": interface.current_dns,
        "dns_leak_status": interface.dns_leak_status,
        "external_ipv4": interface.external_ipv4,
        "external_ipv6": interface.external_ipv6,
        "egress_isp": interface.egress_isp,
        "egress_country": interface.egress_country,
        "default_gateway": interface.default_gateway,
        "metric": interface.metric,
        "vpn_server_ip": interface.vpn_server_ip,
        "carries_vpn": interface.carries_vpn,
    }


def export_to_json(
    interfaces: List[InterfaceInfo],
    indent: int = 2,
    include_metadata: bool = True
) -> str:
    """
    Export network interface data to JSON format.
    
    Args:
        interfaces: List of InterfaceInfo objects to export
        indent: Number of spaces for JSON indentation (default: 2)
        include_metadata: Include timestamp and summary metadata (default: True)
        
    Returns:
        JSON string representation of network data
        
    Examples:
        >>> interfaces = [InterfaceInfo.create_empty("eth0")]
        >>> json_str = export_to_json(interfaces)
        >>> print(json_str)
        {
          "metadata": { ... },
          "interfaces": [ ... ]
        }
    """
    data: Dict[str, Any] = {}
    
    if include_metadata:
        # Add metadata about the export
        data["metadata"] = {
            "timestamp": datetime.now().isoformat(),
            "interface_count": len(interfaces),
            "tool": "netcheck",
            "version": "1.0",
        }
        
        # Add summary statistics
        vpn_interfaces = [i for i in interfaces if i.interface_type == "vpn"]
        leak_detected = any(i.dns_leak_status == "LEAK" for i in interfaces)
        
        data["metadata"]["summary"] = {
            "vpn_active": len(vpn_interfaces) > 0,
            "vpn_interfaces": len(vpn_interfaces),
            "dns_leak_detected": leak_detected,
        }
    
    # Convert interfaces to dictionaries
    data["interfaces"] = [_interface_to_dict(i) for i in interfaces]
    
    return json.dumps(data, indent=indent, ensure_ascii=False)


def export_to_csv(
    interfaces: List[InterfaceInfo],
    include_header: bool = True,
    delimiter: str = ","
) -> str:
    """
    Export network interface data to CSV format.
    
    CSV format is flattened - DNS servers are joined with semicolons.
    
    Args:
        interfaces: List of InterfaceInfo objects to export
        include_header: Include column headers as first row (default: True)
        delimiter: CSV delimiter character (default: ",")
        
    Returns:
        CSV string representation of network data
        
    Examples:
        >>> interfaces = [InterfaceInfo.create_empty("eth0")]
        >>> csv_str = export_to_csv(interfaces)
        >>> print(csv_str)
        name,interface_type,device,...
        eth0,N/A,N/A,...
    """
    output = StringIO()
    
    # Define CSV columns (matches table display order)
    fieldnames = [
        "name",
        "interface_type",
        "device",
        "internal_ipv4",
        "internal_ipv6",
        "dns_servers",  # Will be joined with semicolons
        "current_dns",
        "dns_leak_status",
        "external_ipv4",
        "external_ipv6",
        "egress_isp",
        "egress_country",
        "default_gateway",
        "metric",
        "vpn_server_ip",
        "carries_vpn",
    ]
    
    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
        delimiter=delimiter,
        lineterminator="\n"
    )
    
    if include_header:
        writer.writeheader()
    
    # Write data rows
    for interface in interfaces:
        row = _interface_to_dict(interface)
        
        # Flatten DNS servers list to semicolon-separated string
        row["dns_servers"] = ";".join(row["dns_servers"]) if row["dns_servers"] else ""
        
        # Convert boolean to string
        row["carries_vpn"] = "true" if row["carries_vpn"] else "false"
        
        # Handle None values
        row["current_dns"] = row["current_dns"] or ""
        row["vpn_server_ip"] = row["vpn_server_ip"] or ""
        
        writer.writerow(row)
    
    return output.getvalue()


def save_json(interfaces: List[InterfaceInfo], filepath: str) -> None:
    """
    Save network interface data to JSON file.
    
    Args:
        interfaces: List of InterfaceInfo objects to save
        filepath: Path to output JSON file
        
    Raises:
        IOError: If file cannot be written
        
    Examples:
        >>> interfaces = collect_network_data()
        >>> save_json(interfaces, "network-state.json")
    """
    json_str = export_to_json(interfaces)
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(json_str)


def save_csv(interfaces: List[InterfaceInfo], filepath: str) -> None:
    """
    Save network interface data to CSV file.
    
    Args:
        interfaces: List of InterfaceInfo objects to save
        filepath: Path to output CSV file
        
    Raises:
        IOError: If file cannot be written
        
    Examples:
        >>> interfaces = collect_network_data()
        >>> save_csv(interfaces, "network-state.csv")
    """
    csv_str = export_to_csv(interfaces)
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(csv_str)
