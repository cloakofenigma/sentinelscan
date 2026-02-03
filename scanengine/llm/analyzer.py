"""
LLM Security Analyzer - High-level LLM-based security analysis
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from ..models import Finding, Severity, Confidence, Location
from .client import LLMClient, LLMConfig, LLMResponse
from .prompts import SecurityPrompts, PromptTemplate

logger = logging.getLogger(__name__)


@dataclass
class EnhancedFinding:
    """A finding enhanced with LLM analysis"""
    original: Finding
    explanation: Optional[Dict[str, Any]] = None
    remediation: Optional[Dict[str, Any]] = None
    false_positive_analysis: Optional[Dict[str, Any]] = None
    adjusted_severity: Optional[Severity] = None
    adjusted_confidence: Optional[Confidence] = None
    llm_verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        result = self.original.to_dict()
        result['llm_analysis'] = {
            'verified': self.llm_verified,
            'explanation': self.explanation,
            'remediation': self.remediation,
            'false_positive_analysis': self.false_positive_analysis,
        }
        if self.adjusted_severity:
            result['adjusted_severity'] = self.adjusted_severity.value
        if self.adjusted_confidence:
            result['adjusted_confidence'] = self.adjusted_confidence.value
        return result


@dataclass
class AnalysisResult:
    """Result of LLM analysis"""
    findings: List[EnhancedFinding]
    summary: Dict[str, Any]
    stats: Dict[str, Any]

    @property
    def true_positives(self) -> List[EnhancedFinding]:
        return [f for f in self.findings
                if f.false_positive_analysis and
                f.false_positive_analysis.get('verdict') == 'true_positive']

    @property
    def false_positives(self) -> List[EnhancedFinding]:
        return [f for f in self.findings
                if f.false_positive_analysis and
                f.false_positive_analysis.get('verdict') == 'false_positive']

    @property
    def uncertain(self) -> List[EnhancedFinding]:
        return [f for f in self.findings
                if f.false_positive_analysis and
                f.false_positive_analysis.get('verdict') == 'uncertain']


class LLMSecurityAnalyzer:
    """
    High-level LLM-based security analyzer.
    Provides methods for:
    - Explaining vulnerabilities
    - Generating remediations
    - Analyzing false positives
    - Batch analysis and prioritization
    """

    def __init__(self, client: Optional[LLMClient] = None, config: Optional[LLMConfig] = None):
        self.client = client or LLMClient(config)
        self._content_cache: Dict[str, str] = {}

    @property
    def is_available(self) -> bool:
        """Check if LLM analysis is available"""
        return self.client.is_available

    def set_content_cache(self, cache: Dict[str, str]):
        """Set the content cache for file lookups"""
        self._content_cache = cache

    def _get_code_snippet(self, finding: Finding, context_lines: int = 10) -> str:
        """Extract code snippet around a finding"""
        file_path = finding.location.file_path
        line_num = finding.location.line_number

        # Use cached content if available
        content = self._content_cache.get(file_path)
        if not content:
            try:
                content = Path(file_path).read_text(encoding='utf-8', errors='ignore')
                self._content_cache[file_path] = content
            except Exception as e:
                logger.debug(f"Could not read file {file_path}: {e}")
                return finding.location.snippet or ""

        lines = content.splitlines()
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)

        # Add line numbers
        snippet_lines = []
        for i, line in enumerate(lines[start:end], start + 1):
            marker = ">>>" if i == line_num else "   "
            snippet_lines.append(f"{marker} {i:4d} | {line}")

        return "\n".join(snippet_lines)

    def _get_extended_context(self, finding: Finding, context_lines: int = 30) -> str:
        """Get extended context around a finding"""
        return self._get_code_snippet(finding, context_lines)

    def _get_language(self, file_path: str) -> str:
        """Determine language from file extension"""
        ext_map = {
            '.java': 'java',
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.xml': 'xml',
            '.yml': 'yaml',
            '.yaml': 'yaml',
            '.properties': 'properties',
        }
        suffix = Path(file_path).suffix.lower()
        return ext_map.get(suffix, 'text')

    def explain_finding(self, finding: Finding, include_context: bool = True) -> Dict[str, Any]:
        """
        Generate a detailed explanation of a vulnerability.

        Args:
            finding: The finding to explain
            include_context: Whether to include surrounding code context

        Returns:
            Dict with explanation details
        """
        if not self.is_available:
            return {"error": "LLM not available"}

        prompt = SecurityPrompts.EXPLAIN_VULNERABILITY

        # Build context
        context = ""
        if include_context:
            context = f"**Surrounding Code:**\n```\n{self._get_extended_context(finding, 20)}\n```"

        # Format prompt
        user_message = prompt.format(
            rule_id=finding.rule_id,
            rule_name=finding.rule_name,
            severity=finding.severity.value,
            cwe=finding.cwe or "N/A",
            file_path=finding.location.file_path,
            line_number=finding.location.line_number,
            language=self._get_language(finding.location.file_path),
            code_snippet=self._get_code_snippet(finding),
            context=context,
        )

        try:
            response = self.client.chat(
                messages=[{"role": "user", "content": user_message}],
                system=prompt.system,
            )
            return self._parse_json_response(response.content)
        except Exception as e:
            logger.error(f"Failed to explain finding: {e}")
            return {"error": str(e)}

    def generate_remediation(self, finding: Finding) -> Dict[str, Any]:
        """
        Generate remediation guidance for a finding.

        Args:
            finding: The finding to remediate

        Returns:
            Dict with remediation details
        """
        if not self.is_available:
            return {"error": "LLM not available"}

        prompt = SecurityPrompts.GENERATE_REMEDIATION

        context = f"**Extended Context:**\n```\n{self._get_extended_context(finding, 30)}\n```"

        user_message = prompt.format(
            rule_id=finding.rule_id,
            rule_name=finding.rule_name,
            severity=finding.severity.value,
            cwe=finding.cwe or "N/A",
            file_path=finding.location.file_path,
            line_number=finding.location.line_number,
            language=self._get_language(finding.location.file_path),
            code_snippet=self._get_code_snippet(finding),
            context=context,
        )

        try:
            response = self.client.chat(
                messages=[{"role": "user", "content": user_message}],
                system=prompt.system,
            )
            return self._parse_json_response(response.content)
        except Exception as e:
            logger.error(f"Failed to generate remediation: {e}")
            return {"error": str(e)}

    def analyze_false_positive(
        self,
        finding: Finding,
        additional_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze if a finding is a false positive.

        Args:
            finding: The finding to analyze
            additional_context: Optional additional context

        Returns:
            Dict with false positive analysis
        """
        if not self.is_available:
            return {"error": "LLM not available"}

        prompt = SecurityPrompts.ANALYZE_FALSE_POSITIVE

        add_ctx = ""
        if additional_context:
            add_ctx = f"**Additional Context:**\n{additional_context}"

        user_message = prompt.format(
            rule_id=finding.rule_id,
            rule_name=finding.rule_name,
            severity=finding.severity.value,
            cwe=finding.cwe or "N/A",
            file_path=finding.location.file_path,
            line_number=finding.location.line_number,
            language=self._get_language(finding.location.file_path),
            code_snippet=self._get_code_snippet(finding, 5),
            extended_context=self._get_extended_context(finding, 40),
            additional_context=add_ctx,
        )

        try:
            response = self.client.chat(
                messages=[{"role": "user", "content": user_message}],
                system=prompt.system,
            )
            return self._parse_json_response(response.content)
        except Exception as e:
            logger.error(f"Failed to analyze false positive: {e}")
            return {"error": str(e)}

    def enhance_finding(
        self,
        finding: Finding,
        explain: bool = True,
        remediate: bool = True,
        check_false_positive: bool = True,
    ) -> EnhancedFinding:
        """
        Fully enhance a finding with LLM analysis.

        Args:
            finding: The finding to enhance
            explain: Generate explanation
            remediate: Generate remediation
            check_false_positive: Check for false positive

        Returns:
            EnhancedFinding with all analysis
        """
        enhanced = EnhancedFinding(original=finding)

        if not self.is_available:
            return enhanced

        if explain:
            enhanced.explanation = self.explain_finding(finding)

        if remediate:
            enhanced.remediation = self.generate_remediation(finding)

        if check_false_positive:
            enhanced.false_positive_analysis = self.analyze_false_positive(finding)

            # Adjust severity/confidence based on FP analysis
            if enhanced.false_positive_analysis:
                verdict = enhanced.false_positive_analysis.get('verdict')
                if verdict == 'false_positive':
                    enhanced.adjusted_severity = Severity.INFO
                    enhanced.adjusted_confidence = Confidence.LOW
                elif verdict == 'true_positive':
                    confidence = enhanced.false_positive_analysis.get('confidence', 'medium')
                    enhanced.adjusted_confidence = Confidence[confidence.upper()]

        enhanced.llm_verified = True
        return enhanced

    def analyze_findings(
        self,
        findings: List[Finding],
        max_findings: int = 50,
        check_false_positives: bool = True,
        generate_remediations: bool = False,
    ) -> AnalysisResult:
        """
        Analyze multiple findings.

        Args:
            findings: List of findings to analyze
            max_findings: Maximum findings to analyze (for cost control)
            check_false_positives: Run FP analysis on each
            generate_remediations: Generate remediation for each

        Returns:
            AnalysisResult with enhanced findings
        """
        enhanced_findings = []

        # Sort by severity for priority analysis
        sorted_findings = sorted(
            findings[:max_findings],
            key=lambda f: -f.severity.priority
        )

        for i, finding in enumerate(sorted_findings):
            logger.info(f"Analyzing finding {i+1}/{len(sorted_findings)}: {finding.rule_id}")

            enhanced = self.enhance_finding(
                finding,
                explain=True,
                remediate=generate_remediations,
                check_false_positive=check_false_positives,
            )
            enhanced_findings.append(enhanced)

        # Build summary
        true_pos = len([f for f in enhanced_findings
                       if f.false_positive_analysis and
                       f.false_positive_analysis.get('verdict') == 'true_positive'])
        false_pos = len([f for f in enhanced_findings
                        if f.false_positive_analysis and
                        f.false_positive_analysis.get('verdict') == 'false_positive'])
        uncertain = len([f for f in enhanced_findings
                        if f.false_positive_analysis and
                        f.false_positive_analysis.get('verdict') == 'uncertain'])

        summary = {
            'total_analyzed': len(enhanced_findings),
            'true_positives': true_pos,
            'false_positives': false_pos,
            'uncertain': uncertain,
            'false_positive_rate': f"{false_pos / len(enhanced_findings) * 100:.1f}%" if enhanced_findings else "0%",
        }

        return AnalysisResult(
            findings=enhanced_findings,
            summary=summary,
            stats=self.client.get_stats(),
        )

    def review_code(
        self,
        code: str,
        file_path: str,
        focus_areas: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Perform a general security code review.

        Args:
            code: The code to review
            file_path: Path for language detection
            focus_areas: Specific areas to focus on

        Returns:
            Dict with code review results
        """
        if not self.is_available:
            return {"error": "LLM not available"}

        prompt = SecurityPrompts.CODE_REVIEW
        language = self._get_language(file_path)

        focus = ", ".join(focus_areas) if focus_areas else "SQL injection, XSS, path traversal, authentication, authorization, input validation"

        user_message = prompt.format(
            file_path=file_path,
            language=language,
            code=code,
            focus_areas=focus,
        )

        try:
            response = self.client.chat(
                messages=[{"role": "user", "content": user_message}],
                system=prompt.system,
            )
            return self._parse_json_response(response.content)
        except Exception as e:
            logger.error(f"Failed to review code: {e}")
            return {"error": str(e)}

    def _parse_json_response(self, content: str) -> Dict[str, Any]:
        """Parse JSON from LLM response"""
        content = content.strip()

        # Handle markdown code blocks
        if "```json" in content:
            start = content.find("```json") + 7
            end = content.find("```", start)
            if end > start:
                content = content[start:end]
        elif "```" in content:
            start = content.find("```") + 3
            end = content.find("```", start)
            if end > start:
                content = content[start:end]

        try:
            return json.loads(content.strip())
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON: {e}")
            return {"raw_response": content, "parse_error": str(e)}

    def get_stats(self) -> Dict[str, Any]:
        """Get LLM usage statistics"""
        return self.client.get_stats()


def create_llm_analyzer(
    api_key: Optional[str] = None,
    model: str = "claude-sonnet-4-20250514",
) -> LLMSecurityAnalyzer:
    """Factory function to create an LLM analyzer"""
    config = LLMConfig(api_key=api_key, model=model)
    client = LLMClient(config)
    return LLMSecurityAnalyzer(client)
