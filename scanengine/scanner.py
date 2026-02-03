"""
Main scanner - orchestrates the security scanning process
"""

import os
import time
from pathlib import Path
from typing import List, Optional, Set, Dict
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import Rule, Finding, ScanResult, Severity, Confidence, Location
from .rule_loader import RuleLoader
from .pattern_matcher import PatternMatcher, SecretMatcher
from .context_analyzer import ContextAnalyzer, FileContext, EntropyAnalyzer
from .ast_analyzer import get_ast_analyzer, TREE_SITTER_AVAILABLE
from .dataflow_analyzer import DataflowAnalyzer, analyze_dataflow
from .spring_analyzer import SpringAnalyzer, analyze_spring_application
from .mybatis_analyzer import MybatisAnalyzer, analyze_mybatis_mappers

logger = logging.getLogger(__name__)


class SecurityScanner:
    """Main security scanner that orchestrates the scanning process"""

    # Default file extensions to scan
    DEFAULT_EXTENSIONS = {
        '.java', '.xml', '.properties', '.yml', '.yaml', '.json',
        '.py', '.js', '.ts', '.jsx', '.tsx', '.php', '.go', '.rb',
        '.cs', '.kt', '.scala', '.gradle', '.html', '.htm',
        '.env', '.config', '.conf',
    }

    # Directories to skip
    SKIP_DIRS = {
        '.git', '.svn', '.hg', 'node_modules', '__pycache__',
        '.idea', '.vscode', 'target', 'build', 'dist', 'out',
        'vendor', 'venv', '.venv', 'env', '.env',
        '.gradle', '.mvn', 'bin', 'obj',
    }

    # Files to skip
    SKIP_FILES = {
        '.gitignore', '.dockerignore', 'package-lock.json',
        'yarn.lock', 'pnpm-lock.yaml', 'Pipfile.lock',
        'poetry.lock', 'composer.lock', 'Gemfile.lock',
    }

    # Maximum file size to scan (10 MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024

    def __init__(self, rules_dir: Optional[Path] = None, max_workers: int = 4,
                 enable_context_analysis: bool = True,
                 enable_ast_analysis: bool = True,
                 enable_dataflow_analysis: bool = True,
                 filter_test_files: bool = False,
                 filter_vendor_files: bool = True):
        self.rules_dir = rules_dir
        self.max_workers = max_workers
        self.rule_loader = RuleLoader(rules_dir)
        self.pattern_matcher = PatternMatcher()
        self.secret_matcher = SecretMatcher()
        self.rules: List[Rule] = []
        self._extensions: Set[str] = self.DEFAULT_EXTENSIONS.copy()

        # Phase 2: Context-aware analysis
        self.enable_context_analysis = enable_context_analysis
        self.enable_ast_analysis = enable_ast_analysis and TREE_SITTER_AVAILABLE
        self.filter_test_files = filter_test_files
        self.filter_vendor_files = filter_vendor_files

        # Phase 3: Dataflow analysis and Spring-specific analysis
        self.enable_dataflow_analysis = enable_dataflow_analysis and TREE_SITTER_AVAILABLE
        self.enable_spring_analysis = enable_dataflow_analysis  # Enable when dataflow is enabled

        self.context_analyzer = ContextAnalyzer() if enable_context_analysis else None
        self.entropy_analyzer = EntropyAnalyzer() if enable_context_analysis else None

        # Cache for file contexts and content
        self._file_contexts: Dict[str, FileContext] = {}
        self._content_cache: Dict[str, str] = {}

    def load_rules(self, languages: Optional[List[str]] = None,
                   tags: Optional[List[str]] = None,
                   severity_min: Optional[Severity] = None) -> int:
        """Load and filter rules"""
        all_rules = self.rule_loader.load_all_rules()

        # Filter rules
        self.rules = []
        for rule in all_rules:
            if not rule.enabled:
                continue

            # Filter by language
            if languages:
                if rule.languages and not any(l.lower() in [r.lower() for r in rule.languages] for l in languages):
                    continue

            # Filter by tags
            if tags:
                if not any(t.lower() in [r.lower() for r in rule.tags] for t in tags):
                    continue

            # Filter by minimum severity
            if severity_min:
                if rule.severity.priority < severity_min.priority:
                    continue

            self.rules.append(rule)

        logger.info(f"Loaded {len(self.rules)} rules (filtered from {len(all_rules)})")
        return len(self.rules)

    def scan(self, target_path: str, exclude_patterns: Optional[List[str]] = None) -> ScanResult:
        """Scan a directory or file for security issues"""
        start_time = time.time()
        target = Path(target_path).resolve()

        result = ScanResult(target_path=str(target))

        if not target.exists():
            result.errors.append(f"Target path does not exist: {target}")
            return result

        if not self.rules:
            logger.warning("No rules loaded. Call load_rules() first.")
            result.errors.append("No rules loaded")
            return result

        # Clear caches for new scan
        self._file_contexts.clear()
        self._content_cache.clear()

        # Get list of files to scan
        files_to_scan = self._collect_files(target, exclude_patterns)
        result.rules_applied = len(self.rules)

        logger.info(f"Scanning {len(files_to_scan)} files with {len(self.rules)} rules...")
        if self.enable_context_analysis:
            logger.info("Context-aware analysis enabled (Phase 2)")
        if self.enable_ast_analysis:
            logger.info("AST-based analysis enabled (Phase 2)")
        if self.enable_dataflow_analysis:
            logger.info("Dataflow analysis enabled (Phase 3)")

        # Scan files (with parallel processing)
        if self.max_workers > 1 and len(files_to_scan) > 10:
            findings = self._scan_parallel(files_to_scan)
        else:
            findings = self._scan_sequential(files_to_scan)

        # Phase 3: Run dataflow analysis for inter-procedural taint tracking
        if self.enable_dataflow_analysis:
            dataflow_findings = self._run_dataflow_analysis(files_to_scan)
            findings.extend(dataflow_findings)
            if dataflow_findings:
                logger.info(f"Dataflow analysis found {len(dataflow_findings)} vulnerabilities")

        # Phase 3: Run Spring-specific analysis
        if self.enable_spring_analysis:
            spring_findings = self._run_spring_analysis(files_to_scan)
            findings.extend(spring_findings)
            if spring_findings:
                logger.info(f"Spring analysis found {len(spring_findings)} issues")

        # Phase 3: Run MyBatis mapper analysis
        mybatis_findings = self._run_mybatis_analysis(files_to_scan)
        findings.extend(mybatis_findings)
        if mybatis_findings:
            logger.info(f"MyBatis analysis found {len(mybatis_findings)} SQL injection issues")

        # Phase 2: Apply context-aware false positive filtering
        initial_count = len(findings)
        if self.enable_context_analysis and self.context_analyzer:
            findings = self._apply_context_filtering(findings)
            filtered_count = initial_count - len(findings)
            if filtered_count > 0:
                logger.info(f"Context filtering removed {filtered_count} false positives")

        result.findings = findings
        result.files_scanned = len(files_to_scan)
        result.scan_duration_seconds = time.time() - start_time

        # Sort findings by severity
        result.sort_findings()

        # Deduplicate findings
        result.findings = self._deduplicate_findings(result.findings)

        logger.info(f"Scan complete: {len(result.findings)} findings in {result.scan_duration_seconds:.2f}s")

        return result

    def _collect_files(self, target: Path, exclude_patterns: Optional[List[str]] = None) -> List[Path]:
        """Collect all files to scan"""
        files = []
        exclude_patterns = exclude_patterns or []

        if target.is_file():
            if self._should_scan_file(target, exclude_patterns):
                files.append(target)
            return files

        for root, dirs, filenames in os.walk(target):
            # Filter out directories to skip
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]

            root_path = Path(root)

            for filename in filenames:
                filepath = root_path / filename

                if self._should_scan_file(filepath, exclude_patterns):
                    files.append(filepath)

        return files

    def _should_scan_file(self, filepath: Path, exclude_patterns: List[str]) -> bool:
        """Determine if a file should be scanned"""
        # Skip by filename
        if filepath.name in self.SKIP_FILES:
            return False

        # Skip by extension
        if filepath.suffix.lower() not in self._extensions:
            # Check for files without extension that should be scanned
            if filepath.name not in {'Dockerfile', 'Jenkinsfile', 'Makefile'}:
                return False

        # Skip large files
        try:
            if filepath.stat().st_size > self.MAX_FILE_SIZE:
                logger.debug(f"Skipping large file: {filepath}")
                return False
        except OSError:
            return False

        # Check exclude patterns
        filepath_str = str(filepath)
        for pattern in exclude_patterns:
            import fnmatch
            if fnmatch.fnmatch(filepath_str, pattern):
                return False

        return True

    def _scan_file(self, filepath: Path) -> List[Finding]:
        """Scan a single file"""
        try:
            content = self._read_file(filepath)
            if content is None:
                return []

            filepath_str = str(filepath)

            # Cache content for later context analysis
            self._content_cache[filepath_str] = content

            # Build file context for context-aware filtering
            if self.enable_context_analysis and self.context_analyzer:
                file_context = self.context_analyzer.analyze_file_context(filepath, content)
                self._file_contexts[filepath_str] = file_context

                # Early filtering: skip vendor files if configured
                if self.filter_vendor_files and file_context.is_vendor_file:
                    return []

                # Skip test files if configured
                if self.filter_test_files and file_context.is_test_file:
                    return []

            # Separate rules by type
            secret_rules = [r for r in self.rules if 'secret' in r.tags or 'credentials' in r.tags]
            other_rules = [r for r in self.rules if r not in secret_rules]

            findings = []

            # Run pattern matcher for regular rules
            if other_rules:
                findings.extend(self.pattern_matcher.match_file(filepath, content, other_rules))

            # Run secret matcher for secret-related rules
            if secret_rules:
                secret_findings = self.secret_matcher.match_file(filepath, content, secret_rules)
                # Validate secrets with entropy analysis
                if self.enable_context_analysis and self.entropy_analyzer:
                    secret_findings = [f for f in secret_findings
                                       if self.entropy_analyzer.validate_secret_finding(f)]
                findings.extend(secret_findings)

            # Phase 2: AST-based vulnerability detection
            if self.enable_ast_analysis:
                ast_findings = self._run_ast_analysis(filepath, content)
                findings.extend(ast_findings)

            return findings

        except Exception as e:
            logger.error(f"Error scanning {filepath}: {e}")
            return []

    def _run_ast_analysis(self, filepath: Path, content: str) -> List[Finding]:
        """Run AST-based vulnerability detection"""
        findings = []

        # Determine language from file extension
        file_context = self._file_contexts.get(str(filepath))
        if file_context:
            language = file_context.language
        else:
            language = self._get_language_from_extension(filepath)

        if language == 'unknown':
            return findings

        # Get appropriate AST analyzer
        analyzer = get_ast_analyzer(language)
        if not analyzer:
            return findings

        try:
            # Find dangerous patterns using AST analysis
            dangerous_patterns = analyzer.find_dangerous_patterns(content)

            for pattern in dangerous_patterns:
                cwe_ids = self._get_cwe_for_vuln_type(pattern['type'])
                finding = Finding(
                    rule_id=f"AST-{pattern['type'].upper()}-001",
                    rule_name=f"Potential {pattern['type'].replace('_', ' ').title()} (AST Analysis)",
                    description=f"AST analysis detected a potentially vulnerable pattern: {pattern['sink']} "
                                f"is called with potentially tainted data.",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH if pattern.get('confidence') == 'high' else Confidence.MEDIUM,
                    location=Location(
                        file_path=str(filepath),
                        line_number=pattern['line'],
                        snippet=pattern['code'][:200] if pattern.get('code') else None,
                    ),
                    tags=[pattern['type'], 'ast-analysis', 'taint-tracking'],
                    cwe=f"CWE-{cwe_ids[0]}" if cwe_ids else None,
                    remediation=self._get_remediation_for_vuln_type(pattern['type']),
                )
                findings.append(finding)

        except Exception as e:
            logger.debug(f"AST analysis failed for {filepath}: {e}")

        return findings

    def _get_language_from_extension(self, filepath: Path) -> str:
        """Get language from file extension"""
        ext_map = {
            '.java': 'java',
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
        }
        return ext_map.get(filepath.suffix.lower(), 'unknown')

    def _get_cwe_for_vuln_type(self, vuln_type: str) -> List[int]:
        """Get CWE IDs for vulnerability type"""
        cwe_map = {
            'sql_injection': [89],
            'command_injection': [78],
            'path_traversal': [22],
            'ssrf': [918],
            'deserialization': [502],
            'xss': [79],
        }
        return cwe_map.get(vuln_type, [])

    def _get_remediation_for_vuln_type(self, vuln_type: str) -> str:
        """Get remediation advice for vulnerability type"""
        remediation_map = {
            'sql_injection': "Use parameterized queries or prepared statements. Never concatenate user input into SQL.",
            'command_injection': "Avoid executing shell commands with user input. Use safe APIs or strict input validation.",
            'path_traversal': "Validate and sanitize file paths. Use allowlists and canonicalize paths before use.",
            'ssrf': "Validate and restrict URLs. Use allowlists for permitted hosts and protocols.",
            'deserialization': "Avoid deserializing untrusted data. Use safe serialization formats like JSON.",
            'xss': "Encode output properly for the context. Use Content-Security-Policy headers.",
        }
        return remediation_map.get(vuln_type, "Review and fix the identified security issue.")

    def _run_dataflow_analysis(self, files: List[Path]) -> List[Finding]:
        """Run inter-procedural dataflow analysis (Phase 3)"""
        try:
            # Filter to supported languages (Java, Python)
            supported_files = [f for f in files if f.suffix.lower() in ['.java', '.py']]

            if not supported_files:
                return []

            # Run dataflow analysis using cached content
            analyzer = DataflowAnalyzer()
            analyzer.analyze_files(supported_files, self._content_cache)

            # Get findings
            findings = analyzer.get_findings()
            logger.debug(f"Dataflow analysis: {len(analyzer.vulnerabilities)} vulnerabilities detected")

            return findings

        except Exception as e:
            logger.error(f"Dataflow analysis failed: {e}")
            return []

    def _run_spring_analysis(self, files: List[Path]) -> List[Finding]:
        """Run Spring-specific security analysis (Phase 3)"""
        try:
            # Filter to Spring-relevant files
            spring_files = [f for f in files
                          if f.suffix.lower() in ['.java', '.yml', '.yaml', '.properties']]

            if not spring_files:
                return []

            # Check if this looks like a Spring project
            has_spring_files = any(
                'Controller' in f.name or 'Config' in f.name or
                'Repository' in f.name or 'Service' in f.name or
                f.name in ['application.yml', 'application.yaml', 'application.properties']
                for f in spring_files
            )

            if not has_spring_files:
                # Quick content check
                has_spring_content = False
                for f in spring_files[:10]:  # Check first 10 files
                    content = self._content_cache.get(str(f), '')
                    if '@Controller' in content or '@RestController' in content or \
                       '@SpringBootApplication' in content or '@Service' in content:
                        has_spring_content = True
                        break

                if not has_spring_content:
                    return []

            # Run Spring analysis
            analyzer = SpringAnalyzer()
            findings = analyzer.analyze_files(spring_files, self._content_cache)
            logger.debug(f"Spring analysis: {len(findings)} issues detected, {len(analyzer.endpoints)} endpoints")

            return findings

        except Exception as e:
            logger.error(f"Spring analysis failed: {e}")
            return []

    def _run_mybatis_analysis(self, files: List[Path]) -> List[Finding]:
        """Run MyBatis mapper analysis for SQL injection (Phase 3)"""
        try:
            # Filter to XML files
            xml_files = [f for f in files if f.suffix.lower() == '.xml']

            if not xml_files:
                return []

            # Run MyBatis analysis
            analyzer = MybatisAnalyzer()
            findings = analyzer.analyze_files(xml_files, self._content_cache)

            stats = analyzer.get_statistics()
            if stats['total_mappers'] > 0:
                logger.debug(f"MyBatis analysis: {stats['total_mappers']} mappers, "
                           f"{stats['statements_with_interpolation']}/{stats['total_statements']} "
                           f"statements with interpolation")

            return findings

        except Exception as e:
            logger.error(f"MyBatis analysis failed: {e}")
            return []

    def _apply_context_filtering(self, findings: List[Finding]) -> List[Finding]:
        """Apply context-aware false positive filtering"""
        if not self.context_analyzer:
            return findings

        # Filter out false positives
        filtered = self.context_analyzer.filter_false_positives(
            findings,
            self._file_contexts,
            self._content_cache
        )

        # Adjust confidence based on context
        for finding in filtered:
            filepath = finding.location.file_path
            file_context = self._file_contexts.get(filepath)
            if file_context:
                self.context_analyzer.adjust_confidence(finding, file_context)

        return filtered

    def _scan_sequential(self, files: List[Path]) -> List[Finding]:
        """Scan files sequentially"""
        findings = []
        for filepath in files:
            findings.extend(self._scan_file(filepath))
        return findings

    def _scan_parallel(self, files: List[Path]) -> List[Finding]:
        """Scan files in parallel"""
        findings = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {executor.submit(self._scan_file, f): f for f in files}

            for future in as_completed(future_to_file):
                filepath = future_to_file[future]
                try:
                    file_findings = future.result()
                    findings.extend(file_findings)
                except Exception as e:
                    logger.error(f"Error processing {filepath}: {e}")

        return findings

    def _read_file(self, filepath: Path) -> Optional[str]:
        """Read file content with encoding detection"""
        encodings = ['utf-8', 'latin-1', 'cp1252']

        for encoding in encodings:
            try:
                with open(filepath, 'r', encoding=encoding) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
            except Exception as e:
                logger.debug(f"Error reading {filepath}: {e}")
                return None

        return None

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings (same rule, same location)"""
        seen = set()
        unique = []

        for finding in findings:
            key = (finding.rule_id, finding.location.file_path, finding.location.line_number)
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    def set_extensions(self, extensions: Set[str]) -> None:
        """Set custom file extensions to scan"""
        self._extensions = extensions

    def add_extension(self, extension: str) -> None:
        """Add a file extension to scan"""
        if not extension.startswith('.'):
            extension = '.' + extension
        self._extensions.add(extension)


def create_scanner(rules_dir: Optional[str] = None,
                   languages: Optional[List[str]] = None,
                   severity_min: str = "low",
                   enable_context_analysis: bool = True,
                   enable_ast_analysis: bool = True,
                   enable_dataflow_analysis: bool = True,
                   filter_test_files: bool = False,
                   filter_vendor_files: bool = True) -> SecurityScanner:
    """Factory function to create and configure a scanner

    Args:
        rules_dir: Directory containing YAML rule files
        languages: List of languages to filter rules for
        severity_min: Minimum severity level to report (critical, high, medium, low, info)
        enable_context_analysis: Enable context-aware false positive filtering (Phase 2)
        enable_ast_analysis: Enable AST-based vulnerability detection (Phase 2)
        enable_dataflow_analysis: Enable inter-procedural dataflow analysis (Phase 3)
        filter_test_files: Skip scanning test files entirely
        filter_vendor_files: Skip scanning vendor/third-party files

    Returns:
        Configured SecurityScanner instance
    """
    rules_path = Path(rules_dir) if rules_dir else None
    scanner = SecurityScanner(
        rules_dir=rules_path,
        enable_context_analysis=enable_context_analysis,
        enable_ast_analysis=enable_ast_analysis,
        enable_dataflow_analysis=enable_dataflow_analysis,
        filter_test_files=filter_test_files,
        filter_vendor_files=filter_vendor_files,
    )

    # Map severity string to enum
    severity_map = {
        'critical': Severity.CRITICAL,
        'high': Severity.HIGH,
        'medium': Severity.MEDIUM,
        'low': Severity.LOW,
        'info': Severity.INFO,
    }
    min_sev = severity_map.get(severity_min.lower(), Severity.LOW)

    scanner.load_rules(languages=languages, severity_min=min_sev)

    return scanner
