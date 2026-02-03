"""
Command Line Interface for SentinelScan
"""

import argparse
import sys
import logging
from pathlib import Path
from typing import List, Optional

from .scanner import SecurityScanner, create_scanner
from .reporters import get_reporter, ConsoleReporter
from .models import Severity


def setup_logging(verbose: bool = False, debug: bool = False) -> None:
    """Configure logging"""
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        prog='sentinelscan',
        description='SentinelScan - Detect security vulnerabilities in your codebase',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/project                    # Scan with default settings
  %(prog)s /path/to/project -o report.csv      # Output to CSV file
  %(prog)s /path/to/project -f json -o out.json # JSON output
  %(prog)s /path/to/project -l java -s high    # Java only, high+ severity
  %(prog)s /path/to/project --tags spring sql-injection  # Specific tags
        """
    )

    # Required arguments
    parser.add_argument(
        'target',
        help='Path to the source code directory or file to scan'
    )

    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '-o', '--output',
        help='Output file path (default: stdout)'
    )
    output_group.add_argument(
        '-f', '--format',
        choices=['console', 'csv', 'json', 'sarif'],
        default='console',
        help='Output format (default: console)'
    )
    output_group.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )

    # Filtering options
    filter_group = parser.add_argument_group('Filtering Options')
    filter_group.add_argument(
        '-l', '--language',
        action='append',
        dest='languages',
        help='Filter by language (can be repeated). E.g., -l java -l python'
    )
    filter_group.add_argument(
        '-s', '--severity',
        choices=['critical', 'high', 'medium', 'low', 'info'],
        default='low',
        help='Minimum severity level (default: low)'
    )
    filter_group.add_argument(
        '--tags',
        nargs='+',
        help='Filter by tags. E.g., --tags spring sql-injection'
    )
    filter_group.add_argument(
        '--exclude',
        nargs='+',
        help='Exclude paths matching patterns. E.g., --exclude "*/test/*" "*.spec.js"'
    )

    # Rule options
    rule_group = parser.add_argument_group('Rule Options')
    rule_group.add_argument(
        '-r', '--rules-dir',
        help='Custom rules directory path'
    )
    rule_group.add_argument(
        '--list-rules',
        action='store_true',
        help='List all available rules and exit'
    )

    # Phase 2: Advanced analysis options
    analysis_group = parser.add_argument_group('Advanced Analysis Options (Phase 2)')
    analysis_group.add_argument(
        '--no-context-analysis',
        action='store_true',
        help='Disable context-aware false positive filtering'
    )
    analysis_group.add_argument(
        '--no-ast-analysis',
        action='store_true',
        help='Disable AST-based vulnerability detection'
    )
    analysis_group.add_argument(
        '--skip-test-files',
        action='store_true',
        help='Skip scanning test files entirely'
    )
    analysis_group.add_argument(
        '--include-vendor',
        action='store_true',
        help='Include vendor/third-party files in scan (skipped by default)'
    )

    # Other options
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Debug mode (very verbose)'
    )
    parser.add_argument(
        '-j', '--jobs',
        type=int,
        default=4,
        help='Number of parallel jobs (default: 4)'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 0.5.0'
    )

    return parser.parse_args(args)


def list_rules(rules_dir: Optional[str] = None) -> None:
    """List all available rules"""
    from .rule_loader import RuleLoader

    loader = RuleLoader(Path(rules_dir) if rules_dir else None)
    rules = loader.load_all_rules()

    print(f"\nAvailable Rules ({len(rules)} total):\n")
    print("-" * 80)

    # Group by OWASP category
    by_owasp = {}
    for rule in rules:
        owasp = rule.owasp or 'Other'
        if owasp not in by_owasp:
            by_owasp[owasp] = []
        by_owasp[owasp].append(rule)

    for owasp in sorted(by_owasp.keys()):
        print(f"\n[{owasp}]")
        for rule in sorted(by_owasp[owasp], key=lambda r: r.id):
            severity_color = {
                Severity.CRITICAL: '!',
                Severity.HIGH: '*',
                Severity.MEDIUM: '+',
                Severity.LOW: '-',
                Severity.INFO: ' ',
            }
            marker = severity_color.get(rule.severity, ' ')
            langs = ','.join(rule.languages[:3]) if rule.languages else 'any'
            print(f"  {marker} {rule.id:<20} {rule.name:<40} [{rule.severity.value}] ({langs})")

    print("\n" + "-" * 80)
    print("\nSeverity markers: ! = critical, * = high, + = medium, - = low")
    print(f"\nRule statistics:")
    stats = loader.stats
    for sev, count in stats['by_severity'].items():
        if count > 0:
            print(f"  {sev}: {count}")


def run_scan(args: argparse.Namespace) -> int:
    """Run the security scan"""
    # Determine rules directory
    rules_dir = args.rules_dir
    if not rules_dir:
        # Try default locations
        default_paths = [
            Path(__file__).parent.parent / 'rules',
            Path.cwd() / 'rules',
        ]
        for path in default_paths:
            if path.exists():
                rules_dir = str(path)
                break

    # Create scanner with Phase 2 options
    scanner = SecurityScanner(
        rules_dir=Path(rules_dir) if rules_dir else None,
        max_workers=args.jobs,
        enable_context_analysis=not args.no_context_analysis,
        enable_ast_analysis=not args.no_ast_analysis,
        filter_test_files=args.skip_test_files,
        filter_vendor_files=not args.include_vendor,
    )

    # Load rules with filters
    severity_map = {
        'critical': Severity.CRITICAL,
        'high': Severity.HIGH,
        'medium': Severity.MEDIUM,
        'low': Severity.LOW,
        'info': Severity.INFO,
    }

    rule_count = scanner.load_rules(
        languages=args.languages,
        tags=args.tags,
        severity_min=severity_map.get(args.severity, Severity.LOW)
    )

    if rule_count == 0:
        print("Error: No rules loaded. Check rules directory.", file=sys.stderr)
        return 1

    # Run scan
    result = scanner.scan(
        target_path=args.target,
        exclude_patterns=args.exclude
    )

    # Generate report
    reporter_kwargs = {}
    if args.format == 'console':
        reporter_kwargs['use_colors'] = not args.no_color
        reporter_kwargs['verbose'] = args.verbose

    reporter = get_reporter(args.format, **reporter_kwargs)
    reporter.report(result, args.output)

    # Return exit code based on findings
    if result.errors:
        return 2

    # Exit code based on severity of findings
    if result.get_findings_by_severity(Severity.CRITICAL):
        return 3
    if result.get_findings_by_severity(Severity.HIGH):
        return 2
    if result.findings:
        return 1

    return 0


def main(args: Optional[List[str]] = None) -> int:
    """Main entry point"""
    parsed_args = parse_args(args)

    setup_logging(verbose=parsed_args.verbose, debug=parsed_args.debug)

    # Handle list-rules command
    if parsed_args.list_rules:
        list_rules(parsed_args.rules_dir)
        return 0

    # Validate target exists
    target = Path(parsed_args.target)
    if not target.exists():
        print(f"Error: Target path does not exist: {target}", file=sys.stderr)
        return 1

    try:
        return run_scan(parsed_args)
    except KeyboardInterrupt:
        print("\nScan interrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        if parsed_args.debug:
            raise
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
