"""ASP.NET Framework Analyzer - Stub."""
from typing import Dict, List, Set
from pathlib import Path
from ..base import FrameworkAnalyzer, AnalyzerCapabilities, Endpoint, SecurityConfig
from ..registry import AnalyzerRegistry
from ...models import Finding

@AnalyzerRegistry.register_framework('aspnet')
class AspNetAnalyzer(FrameworkAnalyzer):
    @property
    def name(self) -> str: return "aspnet_analyzer"
    @property
    def framework_name(self) -> str: return "ASP.NET"
    @property
    def base_language(self) -> str: return "csharp"
    @property
    def supported_extensions(self) -> Set[str]: return {'.cs', '.cshtml'}
    @property
    def framework_extensions(self) -> Set[str]: return {'.cs', '.cshtml'}
    @property
    def detection_patterns(self) -> List[str]: return ['file:.csproj', 'content:Microsoft.AspNetCore']
    @property
    def capabilities(self) -> AnalyzerCapabilities: return AnalyzerCapabilities()
    def is_framework_project(self, files: List[Path], content_cache: Dict[str, str]) -> bool:
        for f in files:
            if f.suffix == '.csproj': return True
        return False
    def analyze_file(self, file_path: Path, content: str) -> List[Finding]: return []
    def analyze_files(self, files: List[Path], content_cache: Dict[str, str]) -> List[Finding]: return []
    def get_endpoints(self, files: List[Path], content_cache: Dict[str, str]) -> List[Endpoint]: return []
    def get_security_configs(self, files: List[Path], content_cache: Dict[str, str]) -> List[SecurityConfig]: return []
