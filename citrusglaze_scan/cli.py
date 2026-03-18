"""
CLI argument parsing and main entry point.
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Optional

from .chat_parsers import get_all_sources, parse_directory, ALL_PARSERS
from .scanner import scan_all
from .output import print_full_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="citrusglaze-scan",
        description=(
            "Scan AI chat histories for leaked secrets. "
            "100%% local -- no data leaves your machine."
        ),
        epilog=(
            "Examples:\n"
            "  citrusglaze-scan                     # Scan all AI tools, last 30 days\n"
            "  citrusglaze-scan --tool claude        # Scan only Claude Code\n"
            "  citrusglaze-scan --days 7             # Last 7 days\n"
            "  citrusglaze-scan --json               # JSON output\n"
            "  citrusglaze-scan --path /some/dir     # Scan a specific directory\n"
            "  citrusglaze-scan --verbose            # Show detailed findings\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--tool", "-t",
        type=str,
        choices=list(ALL_PARSERS.keys()),
        action="append",
        help="Scan a specific AI tool (can be repeated). Choices: %(choices)s",
    )

    parser.add_argument(
        "--days", "-d",
        type=int,
        default=30,
        help="Number of days to look back (default: 30, 0 = all time)",
    )

    parser.add_argument(
        "--json", "-j",
        action="store_true",
        dest="json_output",
        help="Output results as JSON",
    )

    parser.add_argument(
        "--path", "-p",
        type=str,
        help="Scan a specific directory or file instead of AI tools",
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed findings with file paths and line numbers",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.2",
    )

    return parser


def _spinner(stop_event, message="Scanning"):
    """Show a simple spinner while scanning."""
    import threading
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    i = 0
    while not stop_event.is_set():
        sys.stderr.write(f"\r  {frames[i % len(frames)]} {message}...")
        sys.stderr.flush()
        stop_event.wait(0.08)
        i += 1
    sys.stderr.write("\r" + " " * (len(message) + 10) + "\r")
    sys.stderr.flush()


def main(argv: Optional[list[str]] = None) -> int:
    """Main entry point for the CLI."""
    import threading

    parser = build_parser()
    args = parser.parse_args(argv)

    # Show banner immediately (unless JSON mode)
    if not args.json_output:
        from .output import print_header
        print_header()

    start_time = time.time()

    # Start spinner
    stop_spinner = threading.Event()
    spinner_thread = None
    if not args.json_output and sys.stderr.isatty():
        spinner_thread = threading.Thread(
            target=_spinner, args=(stop_spinner, "Scanning AI chat histories"),
            daemon=True,
        )
        spinner_thread.start()

    if args.path:
        # Scan a specific directory
        sources = [parse_directory(args.path, days=args.days)]
    else:
        # Scan AI tool histories
        sources = get_all_sources(days=args.days, tools=args.tool)

    # Run the scan
    full_result = scan_all(sources)

    # Stop spinner
    if spinner_thread:
        stop_spinner.set()
        spinner_thread.join()

    # Output results (skip header since we already printed it)
    print_full_report(
        full_result,
        days=args.days,
        json_output=args.json_output,
        verbose=args.verbose,
        skip_header=True,
    )

    elapsed = time.time() - start_time

    if not args.json_output:
        print(f"  Scan completed in {elapsed:.1f}s")
        print()

    # Return non-zero exit code if secrets were found
    return 1 if full_result.total_secrets > 0 else 0


def entry_point():
    """Wrapper for setuptools console_scripts entry point."""
    sys.exit(main())
