#!/usr/bin/env python3
"""
Network Analysis Tool - Main Entry Point

Analyzes network interfaces and displays routing information in a table format.
Queries kernel directly for all local information, uses ipinfo.io for egress data.

Supports export to JSON and CSV formats for automation and integration.
"""

import sys
import argparse
from pathlib import Path
from typing import Optional

from logging_config import setup_logging, get_logger
from orchestrator import check_dependencies, collect_network_data
from display import format_output
from export import export_to_json, export_to_csv, save_json, save_csv

logger = get_logger(__name__)


def parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments.
    
    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description='Network Analysis Tool - Display network interface information',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                      # Normal table output
  %(prog)s -v                   # Verbose output with detailed progress
  %(prog)s --log-file netcheck.log  # Save logs to file
  %(prog)s --export json        # Export to JSON (stdout)
  %(prog)s --export csv         # Export to CSV (stdout)
  %(prog)s --export json --output network.json  # Save JSON to file
  %(prog)s --export csv --output network.csv    # Save CSV to file
        '''
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output with detailed progress information'
    )
    
    parser.add_argument(
        '--log-file',
        type=Path,
        help='Write logs to specified file'
    )
    
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    parser.add_argument(
        '--export',
        choices=['json', 'csv'],
        help='Export data in specified format (json or csv)'
    )
    
    parser.add_argument(
        '--output',
        type=Path,
        help='Output file for export (default: stdout)'
    )
    
    return parser.parse_args()


def main() -> None:
    """Main entry point for the network analysis tool."""
    args = parse_arguments()
    
    # Validate arguments
    if args.output and not args.export:
        print("Error: --output requires --export", file=sys.stderr)
        sys.exit(1)
    
    # Setup logging
    setup_logging(
        verbose=args.verbose,
        log_file=args.log_file,
        use_colors=not args.no_color
    )
    
    logger.info("Network Analysis Tool starting")
    
    # Check dependencies
    if not check_dependencies():
        logger.error("Missing required dependencies")
        logger.info("Please install missing packages and try again")
        sys.exit(1)
    
    logger.debug("All dependencies found")
    
    # Collect network data
    network_data = collect_network_data()
    
    # Handle export mode
    if args.export:
        if args.export == 'json':
            if args.output:
                # Save to file
                save_json(network_data, str(args.output))
                logger.info(f"JSON exported to {args.output}")
            else:
                # Print to stdout
                print(export_to_json(network_data))
        
        elif args.export == 'csv':
            if args.output:
                # Save to file
                save_csv(network_data, str(args.output))
                logger.info(f"CSV exported to {args.output}")
            else:
                # Print to stdout
                print(export_to_csv(network_data))
    
    else:
        # Normal table output
        if args.verbose:
            logger.info(f"\n{'='*60}")
            logger.info("NETWORK INTERFACE SUMMARY")
            logger.info(f"{'='*60}\n")
        else:
            print()
        
        format_output(network_data)
        print()
    
    logger.info("Network Analysis Tool completed successfully")


if __name__ == "__main__":
    main()
