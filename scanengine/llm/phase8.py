"""
Phase 8 LLM Enhancements - Advanced analysis capabilities.

Provides:
- Cost estimation for API calls
- OWASP/CWE-based prioritization
- Async/parallel analysis
- Batch optimization
- Scanner integration helpers
"""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, Tuple
from enum import Enum

from ..models import Finding, Severity, ScanResult
from .analyzer import LLMSecurityAnalyzer, EnhancedFinding, AnalysisResult
from .client import LLMClient, LLMConfig

logger = logging.getLogger(__name__)


# Token pricing (per 1M tokens) - Claude Sonnet as of 2024
PRICING = {
    "claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00},
    "claude-3-5-sonnet-20241022": {"input": 3.00, "output": 15.00},
    "claude-3-opus-20240229": {"input": 15.00, "output": 75.00},
    "claude-3-haiku-20240307": {"input": 0.25, "output": 1.25},
    "default": {"input": 3.00, "output": 15.00},
}

# Average tokens per analysis type
TOKEN_ESTIMATES = {
    "explain": {"input": 1500, "output": 800},
    "remediate": {"input": 2000, "output": 1000},
    "false_positive": {"input": 1500, "output": 500},
    "full": {"input": 3500, "output": 2000},
}

# OWASP Top 10 2021 Risk Weights
OWASP_RISK_WEIGHTS = {
    "A01": 10,  # Broken Access Control
    "A02": 9,   # Cryptographic Failures
    "A03": 9,   # Injection
    "A04": 7,   # Insecure Design
    "A05": 6,   # Security Misconfiguration
    "A06": 5,   # Vulnerable Components
    "A07": 8,   # Auth Failures
    "A08": 6,   # Integrity Failures
    "A09": 4,   # Logging Failures
    "A10": 7,   # SSRF
}

# CWE Severity Multipliers
CWE_SEVERITY = {
    "CWE-89": 1.5,   # SQL Injection
    "CWE-78": 1.5,   # Command Injection
    "CWE-79": 1.2,   # XSS
    "CWE-22": 1.3,   # Path Traversal
    "CWE-798": 1.4,  # Hardcoded Credentials
    "CWE-502": 1.5,  # Insecure Deserialization
    "CWE-918": 1.3,  # SSRF
    "CWE-352": 1.1,  # CSRF
    "CWE-327": 1.0,  # Weak Crypto
    "CWE-862": 1.2,  # Missing Authorization
}


@dataclass
class CostEstimate:
    """Estimated cost for LLM analysis."""
    finding_count: int
    analysis_type: str
    estimated_input_tokens: int
    estimated_output_tokens: int
    estimated_cost_usd: float
    model: str
    breakdown: Dict[str, float] = field(default_factory=dict)

    def __str__(self) -> str:
        return (
            f"Cost Estimate: ${self.estimated_cost_usd:.4f}\n"
            f"  Findings: {self.finding_count}\n"
            f"  Analysis: {self.analysis_type}\n"
            f"  Input tokens: ~{self.estimated_input_tokens:,}\n"
            f"  Output tokens: ~{self.estimated_output_tokens:,}\n"
            f"  Model: {self.model}"
        )


@dataclass
class PrioritizedFinding:
    """A finding with computed priority score."""
    finding: Finding
    priority_score: float
    owasp_weight: int
    cwe_multiplier: float
    severity_score: int
    factors: Dict[str, Any] = field(default_factory=dict)

    @property
    def risk_level(self) -> str:
        if self.priority_score >= 80:
            return "CRITICAL"
        elif self.priority_score >= 60:
            return "HIGH"
        elif self.priority_score >= 40:
            return "MEDIUM"
        elif self.priority_score >= 20:
            return "LOW"
        return "INFO"


class CostEstimator:
    """Estimate costs before running LLM analysis."""

    def __init__(self, model: str = "claude-sonnet-4-20250514"):
        self.model = model
        self.pricing = PRICING.get(model, PRICING["default"])

    def estimate(
        self,
        findings: List[Finding],
        analysis_type: str = "full",
        explain: bool = True,
        remediate: bool = True,
        check_fp: bool = True,
    ) -> CostEstimate:
        """
        Estimate the cost of analyzing findings.

        Args:
            findings: List of findings to analyze
            analysis_type: Type of analysis (explain, remediate, false_positive, full)
            explain: Include explanation analysis
            remediate: Include remediation analysis
            check_fp: Include false positive analysis

        Returns:
            CostEstimate with projected costs
        """
        count = len(findings)

        if analysis_type == "full":
            # Calculate based on selected analyses
            input_tokens = 0
            output_tokens = 0
            if explain:
                input_tokens += TOKEN_ESTIMATES["explain"]["input"] * count
                output_tokens += TOKEN_ESTIMATES["explain"]["output"] * count
            if remediate:
                input_tokens += TOKEN_ESTIMATES["remediate"]["input"] * count
                output_tokens += TOKEN_ESTIMATES["remediate"]["output"] * count
            if check_fp:
                input_tokens += TOKEN_ESTIMATES["false_positive"]["input"] * count
                output_tokens += TOKEN_ESTIMATES["false_positive"]["output"] * count
        else:
            tokens = TOKEN_ESTIMATES.get(analysis_type, TOKEN_ESTIMATES["explain"])
            input_tokens = tokens["input"] * count
            output_tokens = tokens["output"] * count

        input_cost = (input_tokens / 1_000_000) * self.pricing["input"]
        output_cost = (output_tokens / 1_000_000) * self.pricing["output"]
        total_cost = input_cost + output_cost

        return CostEstimate(
            finding_count=count,
            analysis_type=analysis_type,
            estimated_input_tokens=input_tokens,
            estimated_output_tokens=output_tokens,
            estimated_cost_usd=total_cost,
            model=self.model,
            breakdown={
                "input_cost": input_cost,
                "output_cost": output_cost,
            }
        )

    def estimate_from_result(self, result: ScanResult, **kwargs) -> CostEstimate:
        """Estimate cost from a ScanResult."""
        return self.estimate(result.findings, **kwargs)


class FindingPrioritizer:
    """Prioritize findings based on OWASP, CWE, and severity."""

    SEVERITY_SCORES = {
        Severity.CRITICAL: 100,
        Severity.HIGH: 75,
        Severity.MEDIUM: 50,
        Severity.LOW: 25,
        Severity.INFO: 10,
    }

    def prioritize(self, findings: List[Finding]) -> List[PrioritizedFinding]:
        """
        Prioritize findings by risk score.

        Score calculation:
        - Base: Severity score (10-100)
        - Multiply by OWASP weight (0.4-1.0)
        - Multiply by CWE severity (1.0-1.5)

        Args:
            findings: List of findings to prioritize

        Returns:
            List of PrioritizedFinding sorted by priority (highest first)
        """
        prioritized = []

        for finding in findings:
            # Get base severity score
            severity_score = self.SEVERITY_SCORES.get(finding.severity, 50)

            # Get OWASP weight
            owasp = finding.owasp or ""
            owasp_key = owasp.split(":")[0] if ":" in owasp else owasp
            owasp_weight = OWASP_RISK_WEIGHTS.get(owasp_key, 5)

            # Get CWE multiplier
            cwe = finding.cwe or ""
            cwe_multiplier = CWE_SEVERITY.get(cwe, 1.0)

            # Calculate priority score
            # Normalize OWASP weight to 0.4-1.0 range
            owasp_factor = 0.4 + (owasp_weight / 10) * 0.6
            priority_score = severity_score * owasp_factor * cwe_multiplier

            prioritized.append(PrioritizedFinding(
                finding=finding,
                priority_score=priority_score,
                owasp_weight=owasp_weight,
                cwe_multiplier=cwe_multiplier,
                severity_score=severity_score,
                factors={
                    "owasp": owasp,
                    "cwe": cwe,
                    "owasp_factor": owasp_factor,
                }
            ))

        # Sort by priority score (highest first)
        prioritized.sort(key=lambda p: p.priority_score, reverse=True)
        return prioritized

    def get_top_n(self, findings: List[Finding], n: int = 10) -> List[Finding]:
        """Get top N highest priority findings."""
        prioritized = self.prioritize(findings)
        return [p.finding for p in prioritized[:n]]

    def group_by_risk_level(
        self, findings: List[Finding]
    ) -> Dict[str, List[PrioritizedFinding]]:
        """Group findings by computed risk level."""
        prioritized = self.prioritize(findings)
        groups: Dict[str, List[PrioritizedFinding]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": [],
        }
        for p in prioritized:
            groups[p.risk_level].append(p)
        return groups


class ParallelAnalyzer:
    """Run LLM analysis in parallel for faster processing."""

    def __init__(
        self,
        analyzer: LLMSecurityAnalyzer,
        max_workers: int = 4,
    ):
        self.analyzer = analyzer
        self.max_workers = max_workers

    def analyze_parallel(
        self,
        findings: List[Finding],
        explain: bool = True,
        remediate: bool = True,
        check_fp: bool = False,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[EnhancedFinding]:
        """
        Analyze findings in parallel using thread pool.

        Args:
            findings: List of findings to analyze
            explain: Generate explanations
            remediate: Generate remediations
            check_fp: Check for false positives
            progress_callback: Optional callback(completed, total)

        Returns:
            List of EnhancedFinding objects
        """
        results: List[EnhancedFinding] = []
        total = len(findings)
        completed = 0

        def analyze_one(finding: Finding) -> EnhancedFinding:
            return self.analyzer.enhance_finding(
                finding,
                explain=explain,
                remediate=remediate,
                check_false_positive=check_fp,
            )

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_finding = {
                executor.submit(analyze_one, f): f for f in findings
            }

            for future in as_completed(future_to_finding):
                try:
                    enhanced = future.result()
                    results.append(enhanced)
                except Exception as e:
                    finding = future_to_finding[future]
                    logger.error(f"Failed to analyze {finding.rule_id}: {e}")
                    # Add unenhanced finding
                    results.append(EnhancedFinding(original=finding))

                completed += 1
                if progress_callback:
                    progress_callback(completed, total)

        return results


class Phase8Analyzer:
    """
    Phase 8 LLM Analyzer with advanced features.

    Combines:
    - Cost estimation
    - Priority-based selection
    - Parallel analysis
    - Budget-aware processing
    """

    def __init__(
        self,
        client: Optional[LLMClient] = None,
        config: Optional[LLMConfig] = None,
        max_workers: int = 4,
    ):
        self.base_analyzer = LLMSecurityAnalyzer(client, config)
        self.cost_estimator = CostEstimator(
            config.model if config else "claude-sonnet-4-20250514"
        )
        self.prioritizer = FindingPrioritizer()
        self.parallel_analyzer = ParallelAnalyzer(self.base_analyzer, max_workers)

    @property
    def is_available(self) -> bool:
        return self.base_analyzer.is_available

    def set_content_cache(self, cache: Dict[str, str]):
        """Set content cache for file lookups."""
        self.base_analyzer.set_content_cache(cache)

    def estimate_cost(
        self,
        findings: List[Finding],
        explain: bool = True,
        remediate: bool = True,
        check_fp: bool = False,
    ) -> CostEstimate:
        """Estimate cost for analyzing findings."""
        return self.cost_estimator.estimate(
            findings,
            analysis_type="full",
            explain=explain,
            remediate=remediate,
            check_fp=check_fp,
        )

    def analyze_with_budget(
        self,
        findings: List[Finding],
        max_cost_usd: float = 1.0,
        explain: bool = True,
        remediate: bool = True,
        check_fp: bool = False,
        parallel: bool = True,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Tuple[AnalysisResult, CostEstimate]:
        """
        Analyze findings within a budget constraint.

        Prioritizes findings and analyzes as many as budget allows.

        Args:
            findings: All findings to consider
            max_cost_usd: Maximum budget in USD
            explain: Generate explanations
            remediate: Generate remediations
            check_fp: Check false positives
            parallel: Use parallel processing
            progress_callback: Progress callback

        Returns:
            Tuple of (AnalysisResult, CostEstimate)
        """
        if not self.is_available:
            logger.warning("LLM not available, returning empty results")
            return AnalysisResult([], {}, {}), CostEstimate(0, "none", 0, 0, 0.0, "none")

        # Prioritize findings
        prioritized = self.prioritizer.prioritize(findings)

        # Find how many we can afford
        affordable_count = 0
        for i in range(1, len(prioritized) + 1):
            estimate = self.cost_estimator.estimate(
                [p.finding for p in prioritized[:i]],
                explain=explain,
                remediate=remediate,
                check_fp=check_fp,
            )
            if estimate.estimated_cost_usd <= max_cost_usd:
                affordable_count = i
            else:
                break

        if affordable_count == 0:
            logger.warning(f"Budget ${max_cost_usd} too low for any analysis")
            return AnalysisResult([], {"budget_exceeded": True}, {}), \
                   self.cost_estimator.estimate(findings[:1], explain=explain, remediate=remediate, check_fp=check_fp)

        # Select top priority findings within budget
        selected = [p.finding for p in prioritized[:affordable_count]]
        estimate = self.cost_estimator.estimate(
            selected, explain=explain, remediate=remediate, check_fp=check_fp
        )

        logger.info(
            f"Analyzing {affordable_count}/{len(findings)} findings "
            f"(estimated ${estimate.estimated_cost_usd:.4f})"
        )

        # Run analysis
        if parallel and affordable_count > 1:
            enhanced = self.parallel_analyzer.analyze_parallel(
                selected, explain, remediate, check_fp, progress_callback
            )
        else:
            enhanced = []
            for i, finding in enumerate(selected):
                ef = self.base_analyzer.enhance_finding(
                    finding, explain, remediate, check_fp
                )
                enhanced.append(ef)
                if progress_callback:
                    progress_callback(i + 1, len(selected))

        # Build summary
        summary = {
            "total_findings": len(findings),
            "analyzed_findings": len(enhanced),
            "skipped_findings": len(findings) - len(enhanced),
            "budget_usd": max_cost_usd,
            "estimated_cost_usd": estimate.estimated_cost_usd,
        }

        stats = self.base_analyzer.client.get_stats()

        return AnalysisResult(enhanced, summary, stats), estimate

    def analyze_top_n(
        self,
        findings: List[Finding],
        n: int = 10,
        explain: bool = True,
        remediate: bool = True,
        check_fp: bool = False,
        parallel: bool = True,
    ) -> AnalysisResult:
        """
        Analyze top N priority findings.

        Args:
            findings: All findings
            n: Number of top findings to analyze
            explain: Generate explanations
            remediate: Generate remediations
            check_fp: Check false positives
            parallel: Use parallel processing

        Returns:
            AnalysisResult
        """
        top_findings = self.prioritizer.get_top_n(findings, n)

        if parallel and len(top_findings) > 1:
            enhanced = self.parallel_analyzer.analyze_parallel(
                top_findings, explain, remediate, check_fp
            )
        else:
            enhanced = [
                self.base_analyzer.enhance_finding(f, explain, remediate, check_fp)
                for f in top_findings
            ]

        summary = {
            "total_findings": len(findings),
            "analyzed_findings": len(enhanced),
            "selection_method": "top_n_priority",
        }

        return AnalysisResult(enhanced, summary, self.base_analyzer.client.get_stats())


def create_phase8_analyzer(
    api_key: Optional[str] = None,
    model: str = "claude-sonnet-4-20250514",
    max_workers: int = 4,
) -> Phase8Analyzer:
    """
    Factory function to create a Phase8Analyzer.

    Args:
        api_key: Anthropic API key (uses env var if not provided)
        model: Model to use
        max_workers: Max parallel workers

    Returns:
        Configured Phase8Analyzer
    """
    config = LLMConfig(
        api_key=api_key,
        model=model,
    )
    return Phase8Analyzer(config=config, max_workers=max_workers)
