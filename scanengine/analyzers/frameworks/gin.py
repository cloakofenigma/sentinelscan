"""Go Gin Framework Analyzer - Stub."""
from typing import Dict, List, Set
from pathlib import Path
from ..base import FrameworkAnalyzer, AnalyzerCapabilities, Endpoint, SecurityConfig
from ..registry import AnalyzerRegistry
from ...models import Finding

@AnalyzerRegistry.register_framework('gin')
class GinAnalyzer(FrameworkAnalyzer):
    @property
    def name(self) -> str: return "gin_analyzer"
    @property
    def framework_name(self) -> str: return "Gin"
    @property
    def base_language(self) -> str: return "go"
    @property
    def supported_extensions(self) -> Set[str]: return {'.go'}
    @property
    def framework_extensions(self) -> Set[str]: return {'.go'}
    @property
    def detection_patterns(self) -> List[str]: return ['content:github.com/gin-gonic/gin']
    @property
    def capabilities(self) -> AnalyzerCapabilities: return AnalyzerCapabilities()
    def is_framework_project(self, files: List[Path], content_cache: Dict[str, str]) -> bool:
        for content in content_cache.values():
            if 'github.com/gin-gonic/gin' in content: return True
        return False
    def analyze_file(self, file_path: Path, content: str) -> List[Finding]: return []
    def analyze_files(self, files: List[Path], content_cache: Dict[str, str]) -> List[Finding]: return []
    def get_endpoints(self, files: List[Path], content_cache: Dict[str, str]) -> List[Endpoint]: return []
    def get_security_configs(self, files: List[Path], content_cache: Dict[str, str]) -> List[SecurityConfig]: return []
