"""
Analyzer Registry for SentinelScan.

Provides centralized registration and discovery of analyzers:
- Language analyzers (by file extension)
- Framework analyzers (by framework detection)
- IaC analyzers (by file type)
"""

from typing import Dict, List, Optional, Set, Type, Callable
from pathlib import Path
import logging

from .base import (
    BaseAnalyzer,
    LanguageAnalyzer,
    FrameworkAnalyzer,
    IaCAnalyzer,
)

logger = logging.getLogger(__name__)


class AnalyzerRegistry:
    """
    Central registry for all analyzers.

    Provides:
    - Decorator-based registration
    - Extension-based language analyzer lookup
    - Automatic framework detection
    - IaC analyzer discovery
    """

    # Class-level registries
    _language_analyzers: Dict[str, Type[LanguageAnalyzer]] = {}
    _framework_analyzers: Dict[str, Type[FrameworkAnalyzer]] = {}
    _iac_analyzers: Dict[str, Type[IaCAnalyzer]] = {}

    # Extension to language mapping
    _extension_map: Dict[str, str] = {}

    @classmethod
    def register_language(cls, *extensions: str) -> Callable:
        """
        Decorator to register a language analyzer.

        Usage:
            @AnalyzerRegistry.register_language('.go', '.mod')
            class GoAnalyzer(LanguageAnalyzer):
                ...

        Args:
            *extensions: File extensions this analyzer handles (e.g., '.go', '.py')

        Returns:
            Decorator function
        """
        def decorator(analyzer_class: Type[LanguageAnalyzer]) -> Type[LanguageAnalyzer]:
            for ext in extensions:
                ext_lower = ext.lower()
                cls._language_analyzers[ext_lower] = analyzer_class
                cls._extension_map[ext_lower] = analyzer_class.language_name.fget(None)
                logger.debug(f"Registered language analyzer: {analyzer_class.__name__} for {ext_lower}")
            return analyzer_class
        return decorator

    @classmethod
    def register_framework(cls, name: str) -> Callable:
        """
        Decorator to register a framework analyzer.

        Usage:
            @AnalyzerRegistry.register_framework('react')
            class ReactAnalyzer(FrameworkAnalyzer):
                ...

        Args:
            name: Unique framework identifier

        Returns:
            Decorator function
        """
        def decorator(analyzer_class: Type[FrameworkAnalyzer]) -> Type[FrameworkAnalyzer]:
            cls._framework_analyzers[name.lower()] = analyzer_class
            logger.debug(f"Registered framework analyzer: {analyzer_class.__name__} as {name}")
            return analyzer_class
        return decorator

    @classmethod
    def register_iac(cls, *extensions: str) -> Callable:
        """
        Decorator to register an IaC analyzer.

        Usage:
            @AnalyzerRegistry.register_iac('.tf', '.tfvars')
            class TerraformAnalyzer(IaCAnalyzer):
                ...

        Args:
            *extensions: File extensions this analyzer handles

        Returns:
            Decorator function
        """
        def decorator(analyzer_class: Type[IaCAnalyzer]) -> Type[IaCAnalyzer]:
            for ext in extensions:
                ext_lower = ext.lower()
                cls._iac_analyzers[ext_lower] = analyzer_class
                logger.debug(f"Registered IaC analyzer: {analyzer_class.__name__} for {ext_lower}")
            return analyzer_class
        return decorator

    @classmethod
    def get_language_analyzer(cls, extension: str) -> Optional[LanguageAnalyzer]:
        """
        Get a language analyzer instance for the given file extension.

        Args:
            extension: File extension (e.g., '.go', '.py')

        Returns:
            LanguageAnalyzer instance or None
        """
        ext_lower = extension.lower()
        analyzer_class = cls._language_analyzers.get(ext_lower)
        if analyzer_class:
            return analyzer_class()
        return None

    @classmethod
    def get_analyzer_for_file(cls, file_path: Path) -> Optional[BaseAnalyzer]:
        """
        Get the appropriate analyzer for a file.

        Tries language analyzers first, then IaC analyzers.

        Args:
            file_path: Path to the file

        Returns:
            Appropriate analyzer instance or None
        """
        ext = file_path.suffix.lower()

        # Try language analyzer first
        if ext in cls._language_analyzers:
            return cls._language_analyzers[ext]()

        # Try IaC analyzer
        if ext in cls._iac_analyzers:
            return cls._iac_analyzers[ext]()

        # Special handling for files without extension or specific names
        file_name = file_path.name.lower()
        if file_name == 'dockerfile' or file_name.startswith('dockerfile.'):
            if 'dockerfile' in cls._iac_analyzers:
                return cls._iac_analyzers['dockerfile']()

        return None

    @classmethod
    def detect_frameworks(
        cls,
        files: List[Path],
        content_cache: Dict[str, str]
    ) -> List[FrameworkAnalyzer]:
        """
        Auto-detect frameworks used in the project.

        Instantiates each registered framework analyzer and checks
        if the project uses that framework.

        Args:
            files: All files in the project
            content_cache: File contents cache

        Returns:
            List of detected framework analyzers
        """
        detected = []

        for name, analyzer_class in cls._framework_analyzers.items():
            try:
                analyzer = analyzer_class()
                if analyzer.is_framework_project(files, content_cache):
                    detected.append(analyzer)
                    logger.info(f"Detected framework: {analyzer.framework_name}")
            except Exception as e:
                logger.warning(f"Error detecting framework {name}: {e}")

        return detected

    @classmethod
    def get_iac_analyzer(cls, file_path: Path) -> Optional[IaCAnalyzer]:
        """
        Get an IaC analyzer for the given file.

        Args:
            file_path: Path to the file

        Returns:
            IaCAnalyzer instance or None
        """
        ext = file_path.suffix.lower()

        # Direct extension match
        if ext in cls._iac_analyzers:
            return cls._iac_analyzers[ext]()

        # Special file name handling
        file_name = file_path.name.lower()
        if file_name == 'dockerfile' or file_name.startswith('dockerfile.'):
            if 'dockerfile' in cls._iac_analyzers:
                return cls._iac_analyzers['dockerfile']()

        return None

    @classmethod
    def get_all_language_analyzers(cls) -> List[LanguageAnalyzer]:
        """Get instances of all registered language analyzers."""
        seen_classes = set()
        analyzers = []
        for analyzer_class in cls._language_analyzers.values():
            if analyzer_class not in seen_classes:
                seen_classes.add(analyzer_class)
                analyzers.append(analyzer_class())
        return analyzers

    @classmethod
    def get_all_framework_analyzers(cls) -> List[FrameworkAnalyzer]:
        """Get instances of all registered framework analyzers."""
        return [cls() for cls in cls._framework_analyzers.values()]

    @classmethod
    def get_all_iac_analyzers(cls) -> List[IaCAnalyzer]:
        """Get instances of all registered IaC analyzers."""
        seen_classes = set()
        analyzers = []
        for analyzer_class in cls._iac_analyzers.values():
            if analyzer_class not in seen_classes:
                seen_classes.add(analyzer_class)
                analyzers.append(analyzer_class())
        return analyzers

    @classmethod
    def get_supported_extensions(cls) -> Set[str]:
        """Get all file extensions that have registered analyzers."""
        extensions = set(cls._language_analyzers.keys())
        extensions.update(cls._iac_analyzers.keys())
        return extensions

    @classmethod
    def get_supported_languages(cls) -> List[str]:
        """Get list of supported programming languages."""
        languages = set()
        for analyzer_class in cls._language_analyzers.values():
            try:
                # Try to get language_name from class
                lang = analyzer_class.language_name.fget(None)
                if lang:
                    languages.add(lang)
            except Exception:
                pass
        return sorted(languages)

    @classmethod
    def get_supported_frameworks(cls) -> List[str]:
        """Get list of supported frameworks."""
        return sorted(cls._framework_analyzers.keys())

    @classmethod
    def get_supported_iac_types(cls) -> List[str]:
        """Get list of supported IaC types."""
        iac_types = set()
        for analyzer_class in cls._iac_analyzers.values():
            try:
                iac_type = analyzer_class.iac_type.fget(None)
                if iac_type:
                    iac_types.add(iac_type)
            except Exception:
                pass
        return sorted(iac_types)

    @classmethod
    def clear_registry(cls):
        """Clear all registrations (useful for testing)."""
        cls._language_analyzers.clear()
        cls._framework_analyzers.clear()
        cls._iac_analyzers.clear()
        cls._extension_map.clear()

    @classmethod
    def stats(cls) -> Dict[str, int]:
        """Get registration statistics."""
        return {
            'language_analyzers': len(set(cls._language_analyzers.values())),
            'framework_analyzers': len(cls._framework_analyzers),
            'iac_analyzers': len(set(cls._iac_analyzers.values())),
            'supported_extensions': len(cls.get_supported_extensions()),
        }


# Convenience function for backward compatibility
def get_analyzer_for_file(file_path: Path) -> Optional[BaseAnalyzer]:
    """Get an analyzer for the given file path."""
    return AnalyzerRegistry.get_analyzer_for_file(file_path)


def detect_frameworks(files: List[Path], content_cache: Dict[str, str]) -> List[FrameworkAnalyzer]:
    """Detect frameworks used in the project."""
    return AnalyzerRegistry.detect_frameworks(files, content_cache)
