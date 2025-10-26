"""Command-line interface for WAF Presence Checker.

This module provides the main CLI entry point for analyzing HTTP observations
to detect potential WAF presence.
"""

import argparse
import logging
import pathlib
import sys
from typing import Optional

from .analyzer import analyze
from .parsers import parse_har, parse_json_obs, parse_raw_headers
from .reporters import to_json, to_text

# Exit codes
EXIT_OK = 0
EXIT_INDETERMINATE = 1
EXIT_WAF_LIKELY = 2

# Configure logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def _auto_fmt(path: str) -> str:
    """Auto-detect file format based on extension.

    Args:
        path: File path to analyze

    Returns:
        Format string: 'har', 'json', or 'raw'
    """
    p = path.lower()
    if p.endswith('.har'):
        return 'har'
    if p.endswith('.json'):
        return 'json'
    return 'raw'


def main(argv: Optional[list] = None) -> int:
    """Main CLI entry point.

    Args:
        argv: Optional command-line arguments (defaults to sys.argv)

    Returns:
        Exit code: EXIT_OK (0), EXIT_INDETERMINATE (1), or EXIT_WAF_LIKELY (2)
    """
    ap = argparse.ArgumentParser(
        description="Offline WAF presence checker (no network calls).",
        epilog="Exit codes: 0=no WAF detected, 1=indeterminate/error, 2=WAF likely present"
    )
    sub = ap.add_subparsers(dest="cmd")

    an = sub.add_parser("analyze", help="Analyze a captured response file.")
    an.add_argument("-i", "--input", required=True, help="Path to header/observation file")
    an.add_argument("--format", choices=["auto", "raw", "json", "har"], default="auto",
                    help="Input format (auto-detected by default)")
    an.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    an.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")

    args = ap.parse_args(argv)

    # Configure logging level
    if hasattr(args, 'verbose') and args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    if args.cmd != "analyze":
        ap.print_help()
        return EXIT_INDETERMINATE

    try:
        # Read input file
        path = pathlib.Path(args.input)
        if not path.exists():
            logger.error(f"File not found: {args.input}")
            print(f"Error: File not found: {args.input}", file=sys.stderr)
            return EXIT_INDETERMINATE

        if not path.is_file():
            logger.error(f"Path is not a file: {args.input}")
            print(f"Error: Path is not a file: {args.input}", file=sys.stderr)
            return EXIT_INDETERMINATE

        logger.info(f"Reading file: {args.input}")
        text = path.read_text(encoding='utf-8', errors='ignore')

        # Determine format
        fmt = args.format if args.format != 'auto' else _auto_fmt(args.input)
        logger.info(f"Using format: {fmt}")

        # Parse input
        if fmt == 'raw':
            ob = parse_raw_headers(text)
        elif fmt == 'json':
            ob = parse_json_obs(text)
        elif fmt == 'har':
            ob = parse_har(text)
        else:
            logger.error(f"Unknown format: {fmt}")
            print(f"Error: Unknown format: {fmt}", file=sys.stderr)
            return EXIT_INDETERMINATE

        # Analyze
        logger.info("Running analysis...")
        report = analyze(ob)

        # Output results
        if args.json:
            print(to_json(report))
        else:
            print(to_text(report))

        # Determine exit code
        if report.likely_waf and report.confidence >= 0.6:
            logger.info(f"WAF detected with confidence {report.confidence}")
            return EXIT_WAF_LIKELY
        if report.confidence == 0.0:
            logger.info("No indicators found")
            return EXIT_INDETERMINATE

        logger.info(f"Low confidence ({report.confidence}), no WAF detected")
        return EXIT_OK

    except ValueError as e:
        logger.error(f"Validation error: {e}")
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_INDETERMINATE
    except Exception as e:
        logger.exception("Unexpected error during analysis")
        print(f"Unexpected error: {e}", file=sys.stderr)
        return EXIT_INDETERMINATE


if __name__ == "__main__":
    raise SystemExit(main())
