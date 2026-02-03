"""
Git Hooks Integration for SentinelScan
"""

from .installer import install_hooks, uninstall_hooks
from .pre_commit import run_pre_commit_scan
from .pre_push import run_pre_push_scan

__all__ = [
    'install_hooks',
    'uninstall_hooks',
    'run_pre_commit_scan',
    'run_pre_push_scan',
]
