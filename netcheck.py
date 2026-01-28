#!/usr/bin/env python3
"""
Network Analysis Tool - Main Entry Point

Analyzes network interfaces and displays routing information in a table format.
Queries kernel directly for all local information, uses ipinfo.io for egress data.
"""

import sys
import argparse
from pathlib import Path

from logging_config import setup_logging, get_logger
from orchestrator import check_dependencies, collect_network_data
from display import format_output

logger = get_logger(__name__)


def parse_arguments():
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
  %(prog)s              # Normal output
  %(prog)s -v           # Verbose output with detailed progress
  %(prog)s --log-file netcheck.log  # Save logs to file
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
    
    return parser.parse_args()


def main():
    """Main entry point for the network analysis tool."""
    args = parse_arguments()
    
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
    
    # Display results
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
