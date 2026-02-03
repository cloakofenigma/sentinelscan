"""
Git Hooks Installer for SentinelScan

Installs and manages git hooks for security scanning.
"""

import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple

# Hook templates
PRE_COMMIT_HOOK = '''#!/bin/bash
# SentinelScan Pre-commit Hook
# Installed by: sentinelscan install-hooks

# Configuration
THRESHOLD="${SECURITY_SCAN_THRESHOLD:-critical}"
RULES_DIR="${SECURITY_RULES_DIR:-}"

# Find SentinelScan
if command -v sentinelscan &> /dev/null; then
    ANALYZER="sentinelscan"
elif command -v python3 &> /dev/null; then
    ANALYZER="python3 -m scanengine.hooks.pre_commit"
else
    echo "Warning: sentinelscan not found, skipping pre-commit scan"
    exit 0
fi

# Run the scan
if [ -n "$RULES_DIR" ]; then
    $ANALYZER --threshold "$THRESHOLD" --rules-dir "$RULES_DIR"
else
    $ANALYZER --threshold "$THRESHOLD"
fi

exit $?
'''

PRE_PUSH_HOOK = '''#!/bin/bash
# SentinelScan Pre-push Hook
# Installed by: sentinelscan install-hooks

# Configuration
THRESHOLD="${SECURITY_PUSH_THRESHOLD:-high}"
RULES_DIR="${SECURITY_RULES_DIR:-}"
COMPARE_BRANCH="${SECURITY_COMPARE_BRANCH:-}"

# Find SentinelScan
if command -v sentinelscan &> /dev/null; then
    ANALYZER="sentinelscan"
elif command -v python3 &> /dev/null; then
    ANALYZER="python3 -m scanengine.hooks.pre_push"
else
    echo "Warning: sentinelscan not found, skipping pre-push scan"
    exit 0
fi

# Build command
CMD="$ANALYZER --threshold $THRESHOLD"
if [ -n "$RULES_DIR" ]; then
    CMD="$CMD --rules-dir $RULES_DIR"
fi
if [ -n "$COMPARE_BRANCH" ]; then
    CMD="$CMD --compare $COMPARE_BRANCH"
fi

# Run the scan
$CMD

exit $?
'''


def get_git_hooks_dir(repo_path: Optional[str] = None) -> Optional[str]:
    """Get the git hooks directory for a repository."""
    if repo_path is None:
        try:
            result = subprocess.run(
                ['git', 'rev-parse', '--show-toplevel'],
                capture_output=True,
                text=True,
                check=True
            )
            repo_path = result.stdout.strip()
        except subprocess.CalledProcessError:
            return None

    hooks_dir = os.path.join(repo_path, '.git', 'hooks')
    if os.path.isdir(hooks_dir):
        return hooks_dir

    return None


def backup_existing_hook(hook_path: str) -> Optional[str]:
    """Backup existing hook if present."""
    if os.path.exists(hook_path):
        backup_path = f"{hook_path}.backup"
        counter = 1
        while os.path.exists(backup_path):
            backup_path = f"{hook_path}.backup.{counter}"
            counter += 1

        os.rename(hook_path, backup_path)
        return backup_path
    return None


def install_hook(hooks_dir: str, hook_name: str, hook_content: str) -> Tuple[bool, str]:
    """Install a single hook."""
    hook_path = os.path.join(hooks_dir, hook_name)

    # Backup existing
    backup = backup_existing_hook(hook_path)

    try:
        # Write hook
        with open(hook_path, 'w') as f:
            f.write(hook_content)

        # Make executable
        os.chmod(hook_path, os.stat(hook_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        msg = f"Installed {hook_name}"
        if backup:
            msg += f" (backup: {os.path.basename(backup)})"

        return True, msg

    except Exception as e:
        return False, f"Failed to install {hook_name}: {e}"


def install_hooks(
    repo_path: Optional[str] = None,
    pre_commit: bool = True,
    pre_push: bool = True,
    commit_threshold: str = 'critical',
    push_threshold: str = 'high',
    rules_dir: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Install SentinelScan git hooks.

    Args:
        repo_path: Path to git repository (default: current directory)
        pre_commit: Install pre-commit hook
        pre_push: Install pre-push hook
        commit_threshold: Severity threshold for pre-commit
        push_threshold: Severity threshold for pre-push
        rules_dir: Directory containing security rules

    Returns:
        Tuple of (success, message)
    """
    hooks_dir = get_git_hooks_dir(repo_path)
    if not hooks_dir:
        return False, "Not a git repository or hooks directory not found"

    messages = []
    all_success = True

    if pre_commit:
        # Customize hook content with thresholds
        hook_content = PRE_COMMIT_HOOK.replace(
            'THRESHOLD="${SECURITY_SCAN_THRESHOLD:-critical}"',
            f'THRESHOLD="${{SECURITY_SCAN_THRESHOLD:-{commit_threshold}}}"'
        )
        if rules_dir:
            hook_content = hook_content.replace(
                'RULES_DIR="${SECURITY_RULES_DIR:-}"',
                f'RULES_DIR="${{SECURITY_RULES_DIR:-{rules_dir}}}"'
            )

        success, msg = install_hook(hooks_dir, 'pre-commit', hook_content)
        messages.append(msg)
        all_success = all_success and success

    if pre_push:
        hook_content = PRE_PUSH_HOOK.replace(
            'THRESHOLD="${SECURITY_PUSH_THRESHOLD:-high}"',
            f'THRESHOLD="${{SECURITY_PUSH_THRESHOLD:-{push_threshold}}}"'
        )
        if rules_dir:
            hook_content = hook_content.replace(
                'RULES_DIR="${SECURITY_RULES_DIR:-}"',
                f'RULES_DIR="${{SECURITY_RULES_DIR:-{rules_dir}}}"'
            )

        success, msg = install_hook(hooks_dir, 'pre-push', hook_content)
        messages.append(msg)
        all_success = all_success and success

    # Create summary
    summary = '\n'.join(messages)
    if all_success:
        summary = f"✓ Git hooks installed successfully!\n{summary}\n\nConfiguration:\n" \
                  f"  Pre-commit threshold: {commit_threshold}\n" \
                  f"  Pre-push threshold: {push_threshold}\n" \
                  f"  Rules directory: {rules_dir or 'auto-detect'}\n\n" \
                  f"Environment variables:\n" \
                  f"  SECURITY_SCAN_THRESHOLD - Override pre-commit threshold\n" \
                  f"  SECURITY_PUSH_THRESHOLD - Override pre-push threshold\n" \
                  f"  SECURITY_RULES_DIR - Override rules directory\n" \
                  f"  SECURITY_COMPARE_BRANCH - Override comparison branch"

    return all_success, summary


def uninstall_hooks(
    repo_path: Optional[str] = None,
    pre_commit: bool = True,
    pre_push: bool = True,
    restore_backup: bool = True
) -> Tuple[bool, str]:
    """
    Uninstall SentinelScan git hooks.

    Args:
        repo_path: Path to git repository
        pre_commit: Uninstall pre-commit hook
        pre_push: Uninstall pre-push hook
        restore_backup: Restore backup hooks if they exist

    Returns:
        Tuple of (success, message)
    """
    hooks_dir = get_git_hooks_dir(repo_path)
    if not hooks_dir:
        return False, "Not a git repository or hooks directory not found"

    messages = []
    hooks_to_remove = []

    if pre_commit:
        hooks_to_remove.append('pre-commit')
    if pre_push:
        hooks_to_remove.append('pre-push')

    for hook_name in hooks_to_remove:
        hook_path = os.path.join(hooks_dir, hook_name)

        if not os.path.exists(hook_path):
            messages.append(f"  {hook_name}: not installed")
            continue

        # Check if it's our hook
        with open(hook_path, 'r') as f:
            content = f.read()

        if 'SentinelScan' not in content:
            messages.append(f"  {hook_name}: not a sentinelscan hook, skipping")
            continue

        # Remove hook
        os.remove(hook_path)

        # Restore backup if exists
        backup_path = f"{hook_path}.backup"
        if restore_backup and os.path.exists(backup_path):
            os.rename(backup_path, hook_path)
            messages.append(f"  {hook_name}: removed, backup restored")
        else:
            messages.append(f"  {hook_name}: removed")

    summary = "Git hooks status:\n" + '\n'.join(messages)
    return True, summary


def main():
    """CLI entry point for hook installer."""
    import argparse

    parser = argparse.ArgumentParser(description='SentinelScan Git Hooks Installer')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Install command
    install_parser = subparsers.add_parser('install', help='Install git hooks')
    install_parser.add_argument(
        '--repo', '-r',
        help='Path to git repository (default: current directory)'
    )
    install_parser.add_argument(
        '--no-pre-commit',
        action='store_true',
        help='Skip pre-commit hook installation'
    )
    install_parser.add_argument(
        '--no-pre-push',
        action='store_true',
        help='Skip pre-push hook installation'
    )
    install_parser.add_argument(
        '--commit-threshold',
        choices=['low', 'medium', 'high', 'critical'],
        default='critical',
        help='Pre-commit severity threshold (default: critical)'
    )
    install_parser.add_argument(
        '--push-threshold',
        choices=['low', 'medium', 'high', 'critical'],
        default='high',
        help='Pre-push severity threshold (default: high)'
    )
    install_parser.add_argument(
        '--rules-dir',
        help='Directory containing security rules'
    )

    # Uninstall command
    uninstall_parser = subparsers.add_parser('uninstall', help='Uninstall git hooks')
    uninstall_parser.add_argument(
        '--repo', '-r',
        help='Path to git repository (default: current directory)'
    )
    uninstall_parser.add_argument(
        '--no-restore',
        action='store_true',
        help='Do not restore backup hooks'
    )

    args = parser.parse_args()

    if args.command == 'install':
        success, message = install_hooks(
            repo_path=args.repo,
            pre_commit=not args.no_pre_commit,
            pre_push=not args.no_pre_push,
            commit_threshold=args.commit_threshold,
            push_threshold=args.push_threshold,
            rules_dir=args.rules_dir
        )
        print(message)
        sys.exit(0 if success else 1)

    elif args.command == 'uninstall':
        success, message = uninstall_hooks(
            repo_path=args.repo,
            restore_backup=not args.no_restore
        )
        print(message)
        sys.exit(0 if success else 1)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
