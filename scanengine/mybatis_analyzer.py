"""
MyBatis Mapper Analyzer - Security analysis for MyBatis XML mappers
Detects SQL injection vulnerabilities in MyBatis configurations
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
import logging

from .models import Finding, Severity, Confidence, Location

logger = logging.getLogger(__name__)


@dataclass
class MybatisStatement:
    """Represents a MyBatis mapped statement"""
    id: str
    statement_type: str  # select, insert, update, delete
    sql: str
    file_path: str
    line_number: int
    parameter_type: Optional[str] = None
    result_type: Optional[str] = None
    uses_interpolation: bool = False  # ${} syntax
    uses_parameterization: bool = False  # #{} syntax
    interpolated_params: List[str] = field(default_factory=list)


@dataclass
class MybatisMapper:
    """Represents a MyBatis mapper file"""
    namespace: str
    file_path: str
    statements: List[MybatisStatement] = field(default_factory=list)


class MybatisAnalyzer:
    """
    Analyzes MyBatis mapper files for SQL injection vulnerabilities.
    Detects dangerous ${} interpolation patterns that can lead to SQL injection.
    """

    # MyBatis statement types
    STATEMENT_TYPES = {'select', 'insert', 'update', 'delete'}

    # Pattern for ${} interpolation (vulnerable)
    INTERPOLATION_PATTERN = re.compile(r'\$\{([^}]+)\}')

    # Pattern for #{} parameterization (safe)
    PARAMETERIZATION_PATTERN = re.compile(r'#\{([^}]+)\}')

    # Common dangerous parameter names that likely come from user input
    DANGEROUS_PARAMS = {
        'orderby', 'order', 'sortby', 'sort', 'column', 'field',
        'table', 'tablename', 'columns', 'fields', 'limit', 'offset',
        'groupby', 'group', 'having', 'where', 'condition',
        'name', 'search', 'query', 'keyword', 'filter',
        'id', 'ids', 'value', 'values', 'param', 'input',
    }

    # Parameters that are typically safe (internal use)
    SAFE_PARAMS = {
        'item', 'index', 'collection', 'separator', 'open', 'close',
        '_parameter', '_databaseId',
    }

    def __init__(self):
        self.mappers: List[MybatisMapper] = []

    def analyze_files(self, files: List[Path], content_cache: Dict[str, str] = None) -> List[Finding]:
        """Analyze MyBatis mapper files"""
        content_cache = content_cache or {}
        findings = []

        # Filter to XML files
        xml_files = [f for f in files if f.suffix.lower() == '.xml']

        for file_path in xml_files:
            content = content_cache.get(str(file_path))
            if not content:
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    content_cache[str(file_path)] = content
                except Exception as e:
                    logger.debug(f"Failed to read {file_path}: {e}")
                    continue

            # Check if this is a MyBatis mapper
            if not self._is_mybatis_mapper(content):
                continue

            # Parse and analyze
            mapper_findings = self._analyze_mapper(file_path, content)
            findings.extend(mapper_findings)

        return findings

    def _is_mybatis_mapper(self, content: str) -> bool:
        """Check if content is a MyBatis mapper file"""
        # Check for MyBatis DOCTYPE or namespace
        indicators = [
            '<!DOCTYPE mapper',
            'mybatis.org/dtd/mybatis',
            '<mapper namespace=',
            '<select id=',
            '<insert id=',
            '<update id=',
            '<delete id=',
        ]
        return any(indicator in content for indicator in indicators)

    def _analyze_mapper(self, file_path: Path, content: str) -> List[Finding]:
        """Analyze a single MyBatis mapper file"""
        findings = []
        file_str = str(file_path)
        lines = content.splitlines()

        # Create mapper object
        namespace = self._extract_namespace(content)
        mapper = MybatisMapper(namespace=namespace or "unknown", file_path=file_str)

        # Parse statements using regex (more robust than XML parsing for malformed files)
        statements = self._extract_statements(content, file_str)

        for stmt in statements:
            mapper.statements.append(stmt)

            # Check for SQL injection via interpolation
            if stmt.uses_interpolation:
                for param in stmt.interpolated_params:
                    # Check if this is a dangerous parameter
                    severity, confidence = self._assess_interpolation_risk(param, stmt)

                    if severity:
                        findings.append(Finding(
                            rule_id="MYBATIS-001",
                            rule_name="SQL Injection via MyBatis Interpolation",
                            description=f"MyBatis statement '{stmt.id}' uses ${{}} interpolation for '{param}'. "
                                       f"This allows SQL injection if the parameter comes from user input.",
                            severity=severity,
                            confidence=confidence,
                            location=Location(
                                file_path=file_str,
                                line_number=stmt.line_number,
                                snippet=self._get_context(lines, stmt.line_number, param),
                            ),
                            cwe="CWE-89",
                            owasp="A03",
                            tags=['mybatis', 'sql-injection', 'interpolation'],
                            remediation=f"Replace ${{{param}}} with #{{{param}}} if possible. "
                                       f"If dynamic column/table names are needed, use a whitelist.",
                        ))

            # Check for dynamic SQL with potential issues
            dynamic_findings = self._check_dynamic_sql(stmt, lines)
            findings.extend(dynamic_findings)

        self.mappers.append(mapper)
        return findings

    def _extract_namespace(self, content: str) -> Optional[str]:
        """Extract mapper namespace"""
        match = re.search(r'<mapper\s+namespace\s*=\s*["\']([^"\']+)["\']', content)
        return match.group(1) if match else None

    def _extract_statements(self, content: str, file_path: str) -> List[MybatisStatement]:
        """Extract MyBatis statements from content"""
        statements = []
        lines = content.splitlines()

        # Pattern to match statement opening tags
        stmt_pattern = re.compile(
            r'<(select|insert|update|delete)\s+id\s*=\s*["\']([^"\']+)["\']([^>]*)>',
            re.IGNORECASE
        )

        current_stmt = None
        current_sql = []
        start_line = 0

        for i, line in enumerate(lines, 1):
            # Check for statement start
            match = stmt_pattern.search(line)
            if match:
                # Save previous statement if exists
                if current_stmt:
                    current_stmt.sql = '\n'.join(current_sql)
                    self._analyze_sql_content(current_stmt)
                    statements.append(current_stmt)

                stmt_type = match.group(1).lower()
                stmt_id = match.group(2)
                attrs = match.group(3)

                # Extract attributes
                param_type = self._extract_attr(attrs, 'parameterType')
                result_type = self._extract_attr(attrs, 'resultType')

                current_stmt = MybatisStatement(
                    id=stmt_id,
                    statement_type=stmt_type,
                    sql="",
                    file_path=file_path,
                    line_number=i,
                    parameter_type=param_type,
                    result_type=result_type,
                )
                current_sql = []
                start_line = i

                # Check if SQL starts on same line
                after_tag = line[match.end():]
                if after_tag.strip() and not after_tag.strip().startswith('</'):
                    current_sql.append(after_tag)

            elif current_stmt:
                # Check for statement end
                end_match = re.search(rf'</{current_stmt.statement_type}>', line, re.IGNORECASE)
                if end_match:
                    # Add content before closing tag
                    before_end = line[:end_match.start()]
                    if before_end.strip():
                        current_sql.append(before_end)

                    current_stmt.sql = '\n'.join(current_sql)
                    self._analyze_sql_content(current_stmt)
                    statements.append(current_stmt)
                    current_stmt = None
                    current_sql = []
                else:
                    current_sql.append(line)

        # Handle unclosed statement
        if current_stmt:
            current_stmt.sql = '\n'.join(current_sql)
            self._analyze_sql_content(current_stmt)
            statements.append(current_stmt)

        return statements

    def _extract_attr(self, attrs: str, attr_name: str) -> Optional[str]:
        """Extract attribute value"""
        match = re.search(rf'{attr_name}\s*=\s*["\']([^"\']+)["\']', attrs, re.IGNORECASE)
        return match.group(1) if match else None

    def _analyze_sql_content(self, stmt: MybatisStatement):
        """Analyze SQL content for interpolation patterns"""
        sql = stmt.sql

        # Find ${} interpolations
        interpolations = self.INTERPOLATION_PATTERN.findall(sql)
        if interpolations:
            stmt.uses_interpolation = True
            # Extract base parameter names
            for interp in interpolations:
                # Handle complex expressions like ${item.column}
                base_param = interp.split('.')[0].strip()
                if base_param and base_param not in stmt.interpolated_params:
                    stmt.interpolated_params.append(interp)

        # Find #{} parameterizations
        parameterizations = self.PARAMETERIZATION_PATTERN.findall(sql)
        if parameterizations:
            stmt.uses_parameterization = True

    def _assess_interpolation_risk(self, param: str, stmt: MybatisStatement) -> Tuple[Optional[Severity], Confidence]:
        """Assess the risk level of an interpolation"""
        # Extract base parameter name
        base_param = param.split('.')[0].strip().lower()

        # Skip known safe parameters
        if base_param in self.SAFE_PARAMS:
            return None, Confidence.LOW

        # Check for dangerous parameter names
        is_dangerous = any(dangerous in base_param for dangerous in self.DANGEROUS_PARAMS)

        # ORDER BY, GROUP BY, table names are high risk
        sql_lower = stmt.sql.lower()
        is_in_dangerous_context = (
            'order by' in sql_lower and param.lower() in sql_lower[sql_lower.find('order by'):] or
            'group by' in sql_lower and param.lower() in sql_lower[sql_lower.find('group by'):] or
            re.search(rf'from\s+\$\{{{re.escape(param)}\}}', sql_lower) or
            re.search(rf'join\s+\$\{{{re.escape(param)}\}}', sql_lower) or
            re.search(rf'into\s+\$\{{{re.escape(param)}\}}', sql_lower)
        )

        # Determine severity
        if is_in_dangerous_context:
            return Severity.CRITICAL, Confidence.HIGH
        elif is_dangerous:
            return Severity.HIGH, Confidence.HIGH
        else:
            # Still flag it but with lower confidence
            return Severity.HIGH, Confidence.MEDIUM

    def _check_dynamic_sql(self, stmt: MybatisStatement, lines: List[str]) -> List[Finding]:
        """Check for issues in dynamic SQL constructs"""
        findings = []
        sql = stmt.sql

        # Check for <if> with interpolation
        if_with_interpolation = re.findall(
            r'<if\s+test=["\'][^"\']+["\']>\s*[^<]*\$\{([^}]+)\}',
            sql,
            re.IGNORECASE
        )

        for param in if_with_interpolation:
            base_param = param.split('.')[0].strip().lower()
            if base_param not in self.SAFE_PARAMS:
                findings.append(Finding(
                    rule_id="MYBATIS-002",
                    rule_name="Dynamic SQL with Interpolation",
                    description=f"Dynamic <if> block in '{stmt.id}' uses ${{}} interpolation for '{param}'",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    location=Location(
                        file_path=stmt.file_path,
                        line_number=stmt.line_number,
                        snippet=self._get_context(lines, stmt.line_number, param),
                    ),
                    cwe="CWE-89",
                    owasp="A03",
                    tags=['mybatis', 'sql-injection', 'dynamic-sql'],
                    remediation="Use #{} parameterization or validate input against a whitelist",
                ))

        # Check for <foreach> with table/column interpolation
        foreach_interpolation = re.findall(
            r'<foreach[^>]*>\s*[^<]*\$\{([^}]+)\}',
            sql,
            re.IGNORECASE
        )

        for param in foreach_interpolation:
            # foreach item/index are usually safe
            base_param = param.split('.')[0].strip().lower()
            if base_param not in {'item', 'index', 'collection'}:
                findings.append(Finding(
                    rule_id="MYBATIS-003",
                    rule_name="Foreach with Interpolation",
                    description=f"<foreach> in '{stmt.id}' uses ${{}} interpolation for '{param}'",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    location=Location(
                        file_path=stmt.file_path,
                        line_number=stmt.line_number,
                        snippet=self._get_context(lines, stmt.line_number, param),
                    ),
                    cwe="CWE-89",
                    owasp="A03",
                    tags=['mybatis', 'sql-injection', 'foreach'],
                    remediation="Use #{} parameterization in foreach blocks",
                ))

        # Check for LIKE with interpolation (common vulnerability)
        like_interpolation = re.search(
            r"like\s+['\"]?%?\s*\$\{([^}]+)\}\s*%?['\"]?",
            sql,
            re.IGNORECASE
        )
        if like_interpolation:
            param = like_interpolation.group(1)
            findings.append(Finding(
                rule_id="MYBATIS-004",
                rule_name="LIKE Clause with Interpolation",
                description=f"LIKE clause in '{stmt.id}' uses ${{}} for '{param}'. This is vulnerable to SQL injection.",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                location=Location(
                    file_path=stmt.file_path,
                    line_number=stmt.line_number,
                    snippet=self._get_context(lines, stmt.line_number, param),
                ),
                cwe="CWE-89",
                owasp="A03",
                tags=['mybatis', 'sql-injection', 'like'],
                remediation="Use CONCAT('%', #{param}, '%') or bind variables",
            ))

        return findings

    def _get_context(self, lines: List[str], line_num: int, param: str) -> str:
        """Get context snippet around the vulnerable line"""
        # Find the line containing the parameter
        param_pattern = re.compile(rf'\$\{{{re.escape(param)}', re.IGNORECASE)

        for i in range(max(0, line_num - 1), min(len(lines), line_num + 20)):
            if param_pattern.search(lines[i]):
                return lines[i].strip()

        # Fallback to the statement start line
        if line_num <= len(lines):
            return lines[line_num - 1].strip()

        return f"${{{param}}}"

    def get_mappers(self) -> List[MybatisMapper]:
        """Get all analyzed mappers"""
        return self.mappers

    def get_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics"""
        total_statements = sum(len(m.statements) for m in self.mappers)
        interpolation_statements = sum(
            1 for m in self.mappers for s in m.statements if s.uses_interpolation
        )

        return {
            'total_mappers': len(self.mappers),
            'total_statements': total_statements,
            'statements_with_interpolation': interpolation_statements,
            'interpolation_percentage': (
                (interpolation_statements / total_statements * 100) if total_statements else 0
            ),
        }


def analyze_mybatis_mappers(files: List[Path], content_cache: Dict[str, str] = None) -> List[Finding]:
    """Convenience function to analyze MyBatis mappers"""
    analyzer = MybatisAnalyzer()
    return analyzer.analyze_files(files, content_cache)
