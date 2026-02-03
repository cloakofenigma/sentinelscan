"""
Pre-commit Hook for SentinelScan

Scans only staged files for fast feedback during commits.
"""

import subprocess
import sys
import os
from pathlib import Path
from typing import List, Optional, Tuple

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scanengine import create_scanner, Finding, Severity


def get_staged_files() -> List[str]:
    """Get list of staged files from git."""
    try:
        result = subprocess.run(
            ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACMR'],
            capture_output=True,
            text=True,
            check=True
        )
        files = [f.strip() for f in result.stdout.strip().split('\n') if f.strip()]
        return files
    except subprocess.CalledProcessError:
        return []


def get_repo_root() -> Optional[str]:
    """Get the git repository root directory."""
    try:
        result = subprocess.run(
            ['git', 'rev-parse', '--show-toplevel'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None


def filter_scannable_files(files: List[str], repo_root: str) -> List[str]:
    """Filter files to only those we can scan."""
    scannable_extensions = {
        '.java', '.py', '.js', '.ts', '.jsx', '.tsx',
        '.xml', '.yaml', '.yml', '.json', '.properties',
        '.sql', '.sh', '.bash', '.go', '.rb', '.php'
    }

    scannable = []
    for f in files:
        ext = Path(f).suffix.lower()
        if ext in scannable_extensions:
            full_path = os.path.join(repo_root, f)
            if os.path.exists(full_path):
                scannable.append(full_path)

    return scannable


def format_finding(finding: Finding, repo_root: str) -> str:
    """Format a finding for terminal output."""
    # Get relative path
    rel_path = finding.location.file_path
    if rel_path.startswith(repo_root):
        rel_path = rel_path[len(repo_root):].lstrip('/')

    severity_colors = {
        'critical': '\033[91m',  # Red
        'high': '\033[93m',      # Yellow
        'medium': '\033[94m',    # Blue
        'low': '\033[92m',       # Green
    }
    reset = '\033[0m'

    sev = finding.severity.value
    color = severity_colors.get(sev, '')

    return f"  {color}[{sev.upper()}]{reset} {rel_path}:{finding.location.line_number} - {finding.rule_name}"


def run_pre_commit_scan(
    severity_threshold: str = 'critical',
    rules_dir: Optional[str] = None,
    verbose: bool = False
) -> Tuple[bool, str]:
    """
    Run security scan on staged files.

    Args:
        severity_threshold: Block commit if findings at or above this severity
        rules_dir: Directory containing security rules
        verbose: Show detailed output

    Returns:
        Tuple of (passed, message)
    """
    # Get repo root
    repo_root = get_repo_root()
    if not repo_root:
        return True, "Not in a git repository, skipping scan"

    # Get staged files
    staged_files = get_staged_files()
    if not staged_files:
        return True, "No files staged for commit"

    # Filter to scannable files
    scannable = filter_scannable_files(staged_files, repo_root)
    if not scannable:
        return True, "No scannable files in staged changes"

    # Determine rules directory
    if not rules_dir:
        # Try common locations
        possible_paths = [
            os.path.join(repo_root, 'rules'),
            os.path.join(repo_root, '.sentinelscan', 'rules'),
            os.path.expanduser('~/.sentinelscan/rules'),
            '/usr/share/sentinelscan/rules',
        ]
        for path in possible_paths:
            if os.path.isdir(path):
                rules_dir = path
                break

    # Create scanner
    scanner = create_scanner(
        rules_dir=rules_dir,
        severity_min='low',
        filter_test_files=True,
    )

    # Scan each file
    all_findings: List[Finding] = []
    files_scanned = 0

    for file_path in scannable:
        try:
            result = scanner.scan_file(file_path)
            all_findings.extend(result.findings)
            files_scanned += 1
        except Exception as e:
            if verbose:
                print(f"Warning: Could not scan {file_path}: {e}", file=sys.stderr)

    if not all_findings:
        return True, f"✓ Security scan passed ({files_scanned} files scanned, no issues found)"

    # Filter by threshold
    severity_order = ['low', 'medium', 'high', 'critical']
    threshold_idx = severity_order.index(severity_threshold.lower())

    blocking_findings = [
        f for f in all_findings
        if severity_order.index(f.severity.value) >= threshold_idx
    ]

    # Build output
    output_lines = []
    output_lines.append(f"\n{'='*60}")
    output_lines.append("SECURITY SCAN RESULTS")
    output_lines.append(f"{'='*60}")
    output_lines.append(f"Files scanned: {files_scanned}")
    output_lines.append(f"Total findings: {len(all_findings)}")

    # Group by severity
    by_severity = {}
    for f in all_findings:
        sev = f.severity.value
        by_severity.setdefault(sev, []).append(f)

    output_lines.append("\nFindings by severity:")
    for sev in ['critical', 'high', 'medium', 'low']:
        if sev in by_severity:
            output_lines.append(f"  {sev.upper()}: {len(by_severity[sev])}")

    if blocking_findings:
        output_lines.append(f"\n{'─'*60}")
        output_lines.append(f"BLOCKING ISSUES (severity >= {severity_threshold}):")
        output_lines.append(f"{'─'*60}")

        for finding in blocking_findings[:20]:  # Limit output
            output_lines.append(format_finding(finding, repo_root))

        if len(blocking_findings) > 20:
            output_lines.append(f"  ... and {len(blocking_findings) - 20} more")

        output_lines.append(f"\n{'='*60}")
        output_lines.append("✗ COMMIT BLOCKED - Fix security issues or use --no-verify to bypass")
        output_lines.append(f"{'='*60}\n")

        return False, '\n'.join(output_lines)
    else:
        # Warnings but not blocking
        output_lines.append(f"\n{'─'*60}")
        output_lines.append("WARNINGS (below threshold, not blocking):")
        output_lines.append(f"{'─'*60}")

        for finding in all_findings[:10]:
            output_lines.append(format_finding(finding, repo_root))

        if len(all_findings) > 10:
            output_lines.append(f"  ... and {len(all_findings) - 10} more")

        output_lines.append(f"\n{'='*60}")
        output_lines.append("✓ Commit allowed (warnings present but below threshold)")
        output_lines.append(f"{'='*60}\n")

        return True, '\n'.join(output_lines)


def main():
    """CLI entry point for pre-commit hook."""
    import argparse

    parser = argparse.ArgumentParser(description='SentinelScan Pre-commit Hook')
    parser.add_argument(
        '--threshold', '-t',
        choices=['low', 'medium', 'high', 'critical'],
        default='critical',
        help='Block commits at or above this severity (default: critical)'
    )
    parser.add_argument(
        '--rules-dir', '-r',
        help='Directory containing security rules'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show verbose output'
    )

    args = parser.parse_args()

    passed, message = run_pre_commit_scan(
        severity_threshold=args.threshold,
        rules_dir=args.rules_dir,
        verbose=args.verbose
    )

    print(message)
    sys.exit(0 if passed else 1)


if __name__ == '__main__':
    main()
