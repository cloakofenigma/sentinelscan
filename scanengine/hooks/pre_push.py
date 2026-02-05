"""
Pre-push Hook for SentinelScan

Performs full branch scan and compares against main branch.
"""

import subprocess
import sys
import os
from pathlib import Path
from typing import List, Optional, Tuple, Set

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scanengine import create_scanner, Finding, ScanResult


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


def get_current_branch() -> Optional[str]:
    """Get current branch name."""
    try:
        result = subprocess.run(
            ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None


def get_default_branch() -> str:
    """Get the default branch (main or master)."""
    try:
        # Try to get from remote
        result = subprocess.run(
            ['git', 'symbolic-ref', 'refs/remotes/origin/HEAD'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return result.stdout.strip().split('/')[-1]
    except Exception:
        pass

    # Fallback: check if main or master exists
    for branch in ['main', 'master']:
        result = subprocess.run(
            ['git', 'rev-parse', '--verify', branch],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return branch

    return 'main'


def get_changed_files_since_branch(base_branch: str) -> List[str]:
    """Get files changed between current branch and base branch."""
    try:
        result = subprocess.run(
            ['git', 'diff', '--name-only', f'{base_branch}...HEAD'],
            capture_output=True,
            text=True,
            check=True
        )
        return [f.strip() for f in result.stdout.strip().split('\n') if f.strip()]
    except subprocess.CalledProcessError:
        return []


def get_all_branch_files(repo_root: str) -> List[str]:
    """Get all files in the repository."""
    try:
        result = subprocess.run(
            ['git', 'ls-files'],
            capture_output=True,
            text=True,
            check=True,
            cwd=repo_root
        )
        return [f.strip() for f in result.stdout.strip().split('\n') if f.strip()]
    except subprocess.CalledProcessError:
        return []


def finding_fingerprint(finding: Finding) -> str:
    """Create a unique fingerprint for a finding."""
    return f"{finding.rule_id}:{finding.location.file_path}:{finding.location.line_number}"


def format_finding_brief(finding: Finding, repo_root: str) -> str:
    """Format a finding briefly."""
    rel_path = finding.location.file_path
    if rel_path.startswith(repo_root):
        rel_path = rel_path[len(repo_root):].lstrip('/')

    severity_indicators = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢',
    }

    indicator = severity_indicators.get(finding.severity.value, '⚪')
    return f"  {indicator} [{finding.severity.value.upper()}] {rel_path}:{finding.location.line_number} - {finding.rule_name}"


def run_pre_push_scan(
    severity_threshold: str = 'high',
    rules_dir: Optional[str] = None,
    compare_branch: Optional[str] = None,
    verbose: bool = False
) -> Tuple[bool, str]:
    """
    Run full security scan on branch before push.

    Args:
        severity_threshold: Block push if NEW findings at or above this severity
        rules_dir: Directory containing security rules
        compare_branch: Branch to compare against (default: main/master)
        verbose: Show detailed output

    Returns:
        Tuple of (passed, message)
    """
    # Get repo root
    repo_root = get_repo_root()
    if not repo_root:
        return True, "Not in a git repository, skipping scan"

    current_branch = get_current_branch()
    base_branch = compare_branch or get_default_branch()

    # Skip if pushing to default branch directly
    if current_branch in ['main', 'master', base_branch]:
        # Still scan but don't compare
        pass

    # Determine rules directory
    if not rules_dir:
        possible_paths = [
            os.path.join(repo_root, 'rules'),
            os.path.join(repo_root, '.sentinelscan', 'rules'),
            os.path.expanduser('~/.sentinelscan/rules'),
        ]
        for path in possible_paths:
            if os.path.isdir(path):
                rules_dir = path
                break

    output_lines = []
    output_lines.append(f"\n{'='*70}")
    output_lines.append("SENTINELSCAN - PRE-PUSH SCAN")
    output_lines.append(f"{'='*70}")
    output_lines.append(f"Branch: {current_branch}")
    output_lines.append(f"Compare against: {base_branch}")

    # Create scanner
    scanner = create_scanner(
        rules_dir=rules_dir,
        severity_min='low',
        filter_test_files=True,
        enable_dataflow_analysis=True,
    )

    # Get changed files
    changed_files = get_changed_files_since_branch(base_branch)
    output_lines.append(f"Changed files: {len(changed_files)}")

    # Scan the entire repo (or just changed files for speed)
    output_lines.append(f"\nScanning repository...")

    try:
        result = scanner.scan(repo_root)
    except Exception as e:
        return True, f"Scan error: {e}"

    output_lines.append(f"Files scanned: {result.files_scanned}")
    output_lines.append(f"Total findings: {len(result.findings)}")

    # Identify findings in changed files (new findings)
    changed_file_set: Set[str] = set()
    for f in changed_files:
        changed_file_set.add(os.path.join(repo_root, f))
        changed_file_set.add(f)

    new_findings = [
        f for f in result.findings
        if f.location.file_path in changed_file_set or
           any(f.location.file_path.endswith(cf) for cf in changed_files)
    ]

    output_lines.append(f"Findings in changed files: {len(new_findings)}")

    # Group findings by severity
    severity_order = ['low', 'medium', 'high', 'critical']
    threshold_idx = severity_order.index(severity_threshold.lower())

    blocking_findings = [
        f for f in new_findings
        if severity_order.index(f.severity.value) >= threshold_idx
    ]

    # Summary by severity
    output_lines.append(f"\n{'─'*70}")
    output_lines.append("FINDINGS SUMMARY")
    output_lines.append(f"{'─'*70}")

    by_severity = {}
    for f in result.findings:
        sev = f.severity.value
        by_severity.setdefault(sev, []).append(f)

    for sev in ['critical', 'high', 'medium', 'low']:
        if sev in by_severity:
            in_changed = len([f for f in by_severity[sev] if f in new_findings])
            output_lines.append(f"  {sev.upper():10} Total: {len(by_severity[sev]):4}  In changed files: {in_changed}")

    if blocking_findings:
        output_lines.append(f"\n{'─'*70}")
        output_lines.append(f"NEW BLOCKING ISSUES (severity >= {severity_threshold}):")
        output_lines.append(f"{'─'*70}")

        for finding in blocking_findings[:30]:
            output_lines.append(format_finding_brief(finding, repo_root))

        if len(blocking_findings) > 30:
            output_lines.append(f"  ... and {len(blocking_findings) - 30} more")

        output_lines.append(f"\n{'='*70}")
        output_lines.append("✗ PUSH BLOCKED - New security issues introduced")
        output_lines.append("  Fix the issues above or use --no-verify to bypass")
        output_lines.append(f"{'='*70}\n")

        return False, '\n'.join(output_lines)

    elif new_findings:
        # Warnings in changed files but below threshold
        output_lines.append(f"\n{'─'*70}")
        output_lines.append("WARNINGS IN CHANGED FILES (below blocking threshold):")
        output_lines.append(f"{'─'*70}")

        for finding in new_findings[:15]:
            output_lines.append(format_finding_brief(finding, repo_root))

        if len(new_findings) > 15:
            output_lines.append(f"  ... and {len(new_findings) - 15} more")

    output_lines.append(f"\n{'='*70}")
    output_lines.append("✓ PUSH ALLOWED")
    if new_findings:
        output_lines.append(f"  Note: {len(new_findings)} warnings in changed files (below threshold)")
    output_lines.append(f"{'='*70}\n")

    return True, '\n'.join(output_lines)


def main():
    """CLI entry point for pre-push hook."""
    import argparse

    parser = argparse.ArgumentParser(description='SentinelScan Pre-push Hook')
    parser.add_argument(
        '--threshold', '-t',
        choices=['low', 'medium', 'high', 'critical'],
        default='high',
        help='Block push for NEW findings at or above this severity (default: high)'
    )
    parser.add_argument(
        '--rules-dir', '-r',
        help='Directory containing security rules'
    )
    parser.add_argument(
        '--compare', '-c',
        help='Branch to compare against (default: main/master)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show verbose output'
    )

    args = parser.parse_args()

    passed, message = run_pre_push_scan(
        severity_threshold=args.threshold,
        rules_dir=args.rules_dir,
        compare_branch=args.compare,
        verbose=args.verbose
    )

    print(message)
    sys.exit(0 if passed else 1)


if __name__ == '__main__':
    main()
