"""
Context Assembler - Builds rich context for LLM analysis
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
import logging

from ..models import Finding
from ..call_graph import CallGraph, CallGraphNode

logger = logging.getLogger(__name__)


@dataclass
class CodeContext:
    """Rich context for a code location"""
    file_path: str
    line_number: int
    primary_snippet: str
    imports: List[str] = field(default_factory=list)
    class_context: Optional[str] = None
    method_context: Optional[str] = None
    callers: List[Dict[str, Any]] = field(default_factory=list)
    callees: List[Dict[str, Any]] = field(default_factory=list)
    related_files: List[Dict[str, Any]] = field(default_factory=list)
    annotations: List[str] = field(default_factory=list)
    framework_context: Optional[str] = None

    def to_prompt_context(self) -> str:
        """Format context for LLM prompt"""
        parts = []

        if self.imports:
            parts.append("**Imports:**")
            parts.append("```")
            parts.append("\n".join(self.imports[:20]))  # Limit imports
            parts.append("```\n")

        if self.class_context:
            parts.append("**Class Context:**")
            parts.append(f"```\n{self.class_context}\n```\n")

        if self.annotations:
            parts.append("**Annotations:**")
            parts.append(", ".join(self.annotations) + "\n")

        if self.framework_context:
            parts.append("**Framework Context:**")
            parts.append(self.framework_context + "\n")

        if self.callers:
            parts.append("**Called By:**")
            for caller in self.callers[:5]:
                parts.append(f"  - {caller['method']} in {caller['file']}:{caller['line']}")
            parts.append("")

        if self.callees:
            parts.append("**Calls:**")
            for callee in self.callees[:5]:
                parts.append(f"  - {callee['method']} in {callee['file']}:{callee['line']}")
            parts.append("")

        if self.related_files:
            parts.append("**Related Code:**")
            for related in self.related_files[:3]:
                parts.append(f"\n*{related['file']}:*")
                parts.append(f"```\n{related['snippet']}\n```")

        return "\n".join(parts)


class ContextAssembler:
    """
    Assembles rich context for LLM analysis.
    Extracts surrounding code, imports, class context, and call graph information.
    """

    def __init__(
        self,
        content_cache: Optional[Dict[str, str]] = None,
        call_graph: Optional[CallGraph] = None,
    ):
        self.content_cache = content_cache or {}
        self.call_graph = call_graph

    def set_content_cache(self, cache: Dict[str, str]):
        """Set the content cache"""
        self.content_cache = cache

    def set_call_graph(self, call_graph: CallGraph):
        """Set the call graph for inter-procedural context"""
        self.call_graph = call_graph

    def _get_file_content(self, file_path: str) -> Optional[str]:
        """Get file content from cache or disk"""
        if file_path in self.content_cache:
            return self.content_cache[file_path]

        try:
            content = Path(file_path).read_text(encoding='utf-8', errors='ignore')
            self.content_cache[file_path] = content
            return content
        except Exception as e:
            logger.debug(f"Could not read {file_path}: {e}")
            return None

    def build_context(
        self,
        finding: Finding,
        context_lines: int = 15,
        include_imports: bool = True,
        include_class: bool = True,
        include_call_graph: bool = True,
        include_related: bool = True,
    ) -> CodeContext:
        """
        Build rich context for a finding.

        Args:
            finding: The finding to build context for
            context_lines: Lines of context around finding
            include_imports: Include import statements
            include_class: Include class definition context
            include_call_graph: Include caller/callee information
            include_related: Include related file snippets

        Returns:
            CodeContext with assembled information
        """
        file_path = finding.location.file_path
        line_num = finding.location.line_number
        content = self._get_file_content(file_path)

        context = CodeContext(
            file_path=file_path,
            line_number=line_num,
            primary_snippet="",
        )

        if not content:
            return context

        lines = content.splitlines()

        # Primary snippet
        context.primary_snippet = self._extract_snippet(lines, line_num, context_lines)

        # Imports
        if include_imports:
            context.imports = self._extract_imports(lines, file_path)

        # Class context
        if include_class:
            context.class_context = self._extract_class_context(lines, line_num)
            context.method_context = self._extract_method_context(lines, line_num)

        # Annotations
        context.annotations = self._extract_annotations(lines, line_num)

        # Framework context
        context.framework_context = self._detect_framework_context(content, lines, line_num)

        # Call graph context
        if include_call_graph and self.call_graph:
            context.callers, context.callees = self._extract_call_context(file_path, line_num)

        # Related files
        if include_related:
            context.related_files = self._find_related_code(finding, content)

        return context

    def _extract_snippet(self, lines: List[str], line_num: int, context_lines: int) -> str:
        """Extract code snippet with line numbers"""
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)

        snippet_lines = []
        for i, line in enumerate(lines[start:end], start + 1):
            marker = ">>>" if i == line_num else "   "
            snippet_lines.append(f"{marker} {i:4d} | {line}")

        return "\n".join(snippet_lines)

    def _extract_imports(self, lines: List[str], file_path: str) -> List[str]:
        """Extract import statements"""
        imports = []
        suffix = Path(file_path).suffix.lower()

        for line in lines[:100]:  # Check first 100 lines
            line = line.strip()

            if suffix == '.java':
                if line.startswith('import '):
                    imports.append(line)
                elif line.startswith('package '):
                    imports.insert(0, line)
            elif suffix == '.py':
                if line.startswith('import ') or line.startswith('from '):
                    imports.append(line)
            elif suffix in ['.js', '.ts', '.jsx', '.tsx']:
                if line.startswith('import ') or 'require(' in line:
                    imports.append(line)

        return imports

    def _extract_class_context(self, lines: List[str], line_num: int) -> Optional[str]:
        """Extract enclosing class definition"""
        # Search backwards for class definition
        for i in range(line_num - 1, -1, -1):
            line = lines[i].strip()

            # Java/TypeScript class
            if re.match(r'(public\s+|private\s+|protected\s+)?(abstract\s+)?(class|interface|enum)\s+\w+', line):
                # Get class header (may span multiple lines)
                class_lines = [lines[i]]
                j = i + 1
                while j < len(lines) and '{' not in lines[i]:
                    class_lines.append(lines[j])
                    if '{' in lines[j]:
                        break
                    j += 1
                return '\n'.join(class_lines)

            # Python class
            if line.startswith('class '):
                return line

        return None

    def _extract_method_context(self, lines: List[str], line_num: int) -> Optional[str]:
        """Extract enclosing method/function definition"""
        for i in range(line_num - 1, -1, -1):
            line = lines[i].strip()

            # Java method
            method_match = re.match(
                r'(public|private|protected)?\s*(static)?\s*[\w<>\[\],\s]+\s+(\w+)\s*\([^)]*\)',
                line
            )
            if method_match:
                # Get method signature (may include annotations above)
                method_lines = []
                for j in range(max(0, i - 5), i + 1):
                    method_lines.append(lines[j])
                return '\n'.join(method_lines)

            # Python function
            if line.startswith('def ') or line.startswith('async def '):
                # Include decorators
                method_lines = []
                for j in range(max(0, i - 3), i + 1):
                    method_lines.append(lines[j])
                return '\n'.join(method_lines)

        return None

    def _extract_annotations(self, lines: List[str], line_num: int) -> List[str]:
        """Extract annotations/decorators near the line"""
        annotations = []

        # Check lines above for annotations
        for i in range(max(0, line_num - 10), line_num):
            line = lines[i].strip()

            # Java annotations
            if line.startswith('@'):
                # Extract annotation name
                match = re.match(r'@(\w+)', line)
                if match:
                    annotations.append(match.group(1))

            # Python decorators
            if line.startswith('@'):
                annotations.append(line)

        return annotations

    def _detect_framework_context(self, content: str, lines: List[str], line_num: int) -> Optional[str]:
        """Detect framework-specific context"""
        contexts = []

        # Spring detection
        if '@RestController' in content or '@Controller' in content:
            contexts.append("Spring MVC Controller")

            # Check for specific mappings
            for i in range(max(0, line_num - 5), min(len(lines), line_num + 2)):
                line = lines[i]
                if '@GetMapping' in line:
                    contexts.append("GET endpoint")
                elif '@PostMapping' in line:
                    contexts.append("POST endpoint")
                elif '@PutMapping' in line:
                    contexts.append("PUT endpoint")
                elif '@DeleteMapping' in line:
                    contexts.append("DELETE endpoint")

        if '@Service' in content:
            contexts.append("Spring Service")
        if '@Repository' in content:
            contexts.append("Spring Repository/DAO")

        # MyBatis detection
        if 'mybatis' in content.lower() or '#{' in content or '${' in content:
            contexts.append("MyBatis Mapper")

        # Spring Security
        if 'SecurityFilterChain' in content or '@PreAuthorize' in content:
            contexts.append("Spring Security")

        return ", ".join(contexts) if contexts else None

    def _extract_call_context(
        self,
        file_path: str,
        line_num: int
    ) -> tuple:
        """Extract caller and callee information from call graph"""
        callers = []
        callees = []

        if not self.call_graph:
            return callers, callees

        # Find methods in this file
        methods = self.call_graph.find_methods_in_file(file_path)

        # Find the method containing this line
        containing_method = None
        for method in sorted(methods, key=lambda m: m.signature.line_number):
            if method.signature.line_number <= line_num:
                containing_method = method

        if not containing_method:
            return callers, callees

        # Get callers
        for caller_id in containing_method.callers:
            caller = self.call_graph.get_method(caller_id)
            if caller:
                callers.append({
                    'method': caller.signature.qualified_name,
                    'file': caller.signature.file_path,
                    'line': caller.signature.line_number,
                })

        # Get callees
        for callee_id in containing_method.callees:
            callee = self.call_graph.get_method(callee_id)
            if callee:
                callees.append({
                    'method': callee.signature.qualified_name,
                    'file': callee.signature.file_path,
                    'line': callee.signature.line_number,
                })

        return callers, callees

    def _find_related_code(self, finding: Finding, content: str) -> List[Dict[str, Any]]:
        """Find related code snippets that might be relevant"""
        related = []

        # Extract variable/method names from the finding
        snippet = finding.location.snippet or ""
        identifiers = set(re.findall(r'\b([a-zA-Z_]\w+)\b', snippet))

        # Common patterns to look for
        patterns_to_find = []

        # For SQL injection, look for query execution
        if 'sql' in finding.rule_id.lower() or 'injection' in finding.rule_name.lower():
            patterns_to_find.extend(['executeQuery', 'executeUpdate', 'createQuery', 'prepareStatement'])

        # For path traversal, look for file operations
        if 'path' in finding.rule_id.lower() or 'file' in finding.rule_name.lower():
            patterns_to_find.extend(['new File', 'Files.', 'FileInputStream', 'FileOutputStream'])

        # Search for related patterns in the same file
        lines = content.splitlines()
        for pattern in patterns_to_find:
            for i, line in enumerate(lines, 1):
                if pattern in line and i != finding.location.line_number:
                    # Get a small snippet around this line
                    start = max(0, i - 2)
                    end = min(len(lines), i + 3)
                    snippet = '\n'.join(lines[start:end])

                    related.append({
                        'file': finding.location.file_path,
                        'line': i,
                        'snippet': snippet,
                        'reason': f"Related: contains '{pattern}'",
                    })

                    if len(related) >= 3:
                        return related

        return related

    def build_batch_context(
        self,
        findings: List[Finding],
        group_by_file: bool = True,
    ) -> Dict[str, CodeContext]:
        """
        Build context for multiple findings efficiently.

        Args:
            findings: List of findings
            group_by_file: Group findings by file for efficiency

        Returns:
            Dict mapping finding ID to CodeContext
        """
        contexts = {}

        if group_by_file:
            # Group by file
            by_file: Dict[str, List[Finding]] = {}
            for finding in findings:
                fp = finding.location.file_path
                if fp not in by_file:
                    by_file[fp] = []
                by_file[fp].append(finding)

            # Process each file once
            for file_path, file_findings in by_file.items():
                # Pre-load file content
                self._get_file_content(file_path)

                for finding in file_findings:
                    key = f"{finding.rule_id}:{finding.location.file_path}:{finding.location.line_number}"
                    contexts[key] = self.build_context(finding)
        else:
            for finding in findings:
                key = f"{finding.rule_id}:{finding.location.file_path}:{finding.location.line_number}"
                contexts[key] = self.build_context(finding)

        return contexts


def create_context_assembler(
    content_cache: Optional[Dict[str, str]] = None,
    call_graph: Optional[CallGraph] = None,
) -> ContextAssembler:
    """Factory function to create a context assembler"""
    return ContextAssembler(content_cache, call_graph)
