"""
Export functionality for network analysis data.

Provides JSON and CSV export capabilities for InterfaceInfo data.
Both formats are built-in to Python (no external dependencies).
"""

import json
import csv
from typing import List, Dict, Any
from io import StringIO
from datetime import datetime

from models import InterfaceInfo


def _interface_to_dict(interface: InterfaceInfo) -> Dict[str, Any]:
    """Convert InterfaceInfo to dictionary for serialization."""
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
    """
    data: Dict[str, Any] = {}
    
    if include_metadata:
        data["metadata"] = {
            "timestamp": datetime.now().isoformat(),
            "interface_count": len(interfaces),
            "tool": "netcheck",
            "version": "1.0",
        }
        
        vpn_interfaces = [i for i in interfaces if i.interface_type == "vpn"]
        leak_detected = any(i.dns_leak_status == "LEAK" for i in interfaces)
        
        data["metadata"]["summary"] = {
            "vpn_active": len(vpn_interfaces) > 0,
            "vpn_interfaces": len(vpn_interfaces),
            "dns_leak_detected": leak_detected,
        }
    
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
    """
    output = StringIO()
    
    fieldnames = [
        "name", "interface_type", "device", "internal_ipv4", "internal_ipv6",
        "dns_servers", "current_dns", "dns_leak_status",
        "external_ipv4", "external_ipv6", "egress_isp", "egress_country",
        "default_gateway", "metric", "vpn_server_ip", "carries_vpn",
    ]
    
    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
        delimiter=delimiter,
        lineterminator="\n"
    )
    
    if include_header:
        writer.writeheader()
    
    for interface in interfaces:
        row = _interface_to_dict(interface)
        
        row["dns_servers"] = ";".join(row["dns_servers"]) if row["dns_servers"] else ""
        row["carries_vpn"] = "true" if row["carries_vpn"] else "false"
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
    """
    csv_str = export_to_csv(interfaces)
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(csv_str)
