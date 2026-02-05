"""
Base class for framework analyzers.

Provides common functionality for framework detection and analysis.
"""

from typing import Dict, List, Set
from pathlib import Path
import re

from ..base import FrameworkAnalyzer, Endpoint, SecurityConfig


class BaseFrameworkAnalyzer(FrameworkAnalyzer):
    """Base implementation with common framework detection logic."""

    def is_framework_project(self, files: List[Path], content_cache: Dict[str, str]) -> bool:
        """Detect framework by checking for characteristic files and imports."""
        file_names = {f.name.lower() for f in files}
        file_paths_str = [str(f).lower() for f in files]

        # Check for characteristic files
        for pattern in self.detection_patterns:
            # File name pattern
            if pattern.startswith('file:'):
                target = pattern[5:]
                if target in file_names:
                    return True
            # File content pattern
            elif pattern.startswith('content:'):
                content_pattern = pattern[8:]
                for file_path, content in content_cache.items():
                    if re.search(content_pattern, content):
                        return True
            # Import pattern
            elif pattern.startswith('import:'):
                import_pattern = pattern[7:]
                for file_path, content in content_cache.items():
                    if re.search(import_pattern, content):
                        return True
            # Package.json dependency
            elif pattern.startswith('package:'):
                pkg_name = pattern[8:]
                for file_path, content in content_cache.items():
                    if 'package.json' in file_path:
                        if f'"{pkg_name}"' in content:
                            return True

        return False

    def get_framework_files(self, files: List[Path]) -> List[Path]:
        """Get files relevant to this framework."""
        return [f for f in files if f.suffix.lower() in self.framework_extensions]
