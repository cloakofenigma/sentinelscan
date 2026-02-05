"""Laravel Framework Analyzer - Stub."""
from typing import Dict, List, Set
from pathlib import Path
from ..base import FrameworkAnalyzer, AnalyzerCapabilities, Endpoint, SecurityConfig
from ..registry import AnalyzerRegistry
from ...models import Finding

@AnalyzerRegistry.register_framework('laravel')
class LaravelAnalyzer(FrameworkAnalyzer):
    @property
    def name(self) -> str: return "laravel_analyzer"
    @property
    def framework_name(self) -> str: return "Laravel"
    @property
    def base_language(self) -> str: return "php"
    @property
    def supported_extensions(self) -> Set[str]: return {'.php', '.blade.php'}
    @property
    def framework_extensions(self) -> Set[str]: return {'.php', '.blade.php'}
    @property
    def detection_patterns(self) -> List[str]: return ['file:composer.json', 'content:laravel/framework']
    @property
    def capabilities(self) -> AnalyzerCapabilities: return AnalyzerCapabilities()
    def is_framework_project(self, files: List[Path], content_cache: Dict[str, str]) -> bool:
        for content in content_cache.values():
            if 'laravel/framework' in content: return True
        return False
    def analyze_file(self, file_path: Path, content: str) -> List[Finding]: return []
    def analyze_files(self, files: List[Path], content_cache: Dict[str, str]) -> List[Finding]: return []
    def get_endpoints(self, files: List[Path], content_cache: Dict[str, str]) -> List[Endpoint]: return []
    def get_security_configs(self, files: List[Path], content_cache: Dict[str, str]) -> List[SecurityConfig]: return []
