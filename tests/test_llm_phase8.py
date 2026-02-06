"""Tests for Phase 8 LLM enhancements."""

import pytest
from scanengine.models import Finding, Severity, Confidence, Location
from scanengine.llm.phase8 import (
    CostEstimator,
    FindingPrioritizer,
    PrioritizedFinding,
)


@pytest.fixture
def sample_findings():
    """Create sample findings for testing."""
    return [
        Finding(
            rule_id="SQLI-001",
            rule_name="SQL Injection",
            description="SQL injection vulnerability",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            location=Location("/app/db.py", 10, 0, ""),
            cwe="CWE-89",
            owasp="A03",
        ),
        Finding(
            rule_id="XSS-001",
            rule_name="Cross-Site Scripting",
            description="XSS vulnerability",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            location=Location("/app/views.py", 20, 0, ""),
            cwe="CWE-79",
            owasp="A03",
        ),
        Finding(
            rule_id="LOG-001",
            rule_name="Sensitive Data in Logs",
            description="Logging sensitive data",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            location=Location("/app/utils.py", 30, 0, ""),
            cwe="CWE-532",
            owasp="A09",
        ),
        Finding(
            rule_id="CMD-001",
            rule_name="Command Injection",
            description="Command injection vulnerability",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            location=Location("/app/exec.py", 15, 0, ""),
            cwe="CWE-78",
            owasp="A03",
        ),
    ]


class TestCostEstimator:
    def test_estimate_single_finding(self, sample_findings):
        estimator = CostEstimator()
        estimate = estimator.estimate(sample_findings[:1], analysis_type="explain")

        assert estimate.finding_count == 1
        assert estimate.estimated_cost_usd > 0
        assert estimate.estimated_input_tokens > 0
        assert estimate.estimated_output_tokens > 0

    def test_estimate_multiple_findings(self, sample_findings):
        estimator = CostEstimator()
        estimate = estimator.estimate(sample_findings, analysis_type="full")

        assert estimate.finding_count == 4
        assert estimate.estimated_cost_usd > 0

    def test_estimate_full_analysis(self, sample_findings):
        estimator = CostEstimator()
        estimate = estimator.estimate(
            sample_findings,
            analysis_type="full",
            explain=True,
            remediate=True,
            check_fp=True,
        )

        # Full analysis should cost more than single type
        explain_only = estimator.estimate(sample_findings, analysis_type="explain")
        assert estimate.estimated_cost_usd > explain_only.estimated_cost_usd

    def test_cost_estimate_str(self, sample_findings):
        estimator = CostEstimator()
        estimate = estimator.estimate(sample_findings[:1])

        output = str(estimate)
        assert "Cost Estimate" in output
        assert "$" in output

    def test_different_models_have_different_costs(self, sample_findings):
        sonnet = CostEstimator(model="claude-sonnet-4-20250514")
        haiku = CostEstimator(model="claude-3-haiku-20240307")

        sonnet_est = sonnet.estimate(sample_findings)
        haiku_est = haiku.estimate(sample_findings)

        # Haiku should be cheaper
        assert haiku_est.estimated_cost_usd < sonnet_est.estimated_cost_usd


class TestFindingPrioritizer:
    def test_prioritize_returns_sorted_list(self, sample_findings):
        prioritizer = FindingPrioritizer()
        prioritized = prioritizer.prioritize(sample_findings)

        assert len(prioritized) == 4
        # Should be sorted by priority (highest first)
        for i in range(len(prioritized) - 1):
            assert prioritized[i].priority_score >= prioritized[i + 1].priority_score

    def test_critical_findings_have_higher_priority(self, sample_findings):
        prioritizer = FindingPrioritizer()
        prioritized = prioritizer.prioritize(sample_findings)

        # Critical findings should be at top
        top_two = prioritized[:2]
        for p in top_two:
            assert p.finding.severity == Severity.CRITICAL

    def test_get_top_n(self, sample_findings):
        prioritizer = FindingPrioritizer()
        top_2 = prioritizer.get_top_n(sample_findings, n=2)

        assert len(top_2) == 2
        for f in top_2:
            assert f.severity == Severity.CRITICAL

    def test_group_by_risk_level(self, sample_findings):
        prioritizer = FindingPrioritizer()
        groups = prioritizer.group_by_risk_level(sample_findings)

        assert "CRITICAL" in groups
        assert "HIGH" in groups
        assert "MEDIUM" in groups
        assert "LOW" in groups
        assert "INFO" in groups

        total = sum(len(g) for g in groups.values())
        assert total == 4

    def test_owasp_weight_affects_priority(self):
        prioritizer = FindingPrioritizer()

        # A01 (Broken Access Control) has highest weight
        high_owasp = Finding(
            rule_id="TEST-001",
            rule_name="Test",
            description="Test",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            location=Location("/test.py", 1, 0, ""),
            owasp="A01",
        )

        # A09 (Logging) has lower weight
        low_owasp = Finding(
            rule_id="TEST-002",
            rule_name="Test",
            description="Test",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            location=Location("/test.py", 2, 0, ""),
            owasp="A09",
        )

        prioritized = prioritizer.prioritize([low_owasp, high_owasp])

        # A01 should have higher priority
        assert prioritized[0].finding.owasp == "A01"
        assert prioritized[0].priority_score > prioritized[1].priority_score

    def test_cwe_multiplier_affects_priority(self):
        prioritizer = FindingPrioritizer()

        # SQL Injection has high multiplier
        sql_injection = Finding(
            rule_id="SQL-001",
            rule_name="SQL Injection",
            description="Test",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            location=Location("/test.py", 1, 0, ""),
            cwe="CWE-89",
            owasp="A03",
        )

        # Weak Crypto has lower multiplier
        weak_crypto = Finding(
            rule_id="CRYPTO-001",
            rule_name="Weak Crypto",
            description="Test",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            location=Location("/test.py", 2, 0, ""),
            cwe="CWE-327",
            owasp="A03",
        )

        prioritized = prioritizer.prioritize([weak_crypto, sql_injection])

        # SQL Injection should have higher priority due to CWE multiplier
        assert prioritized[0].finding.cwe == "CWE-89"


class TestPrioritizedFinding:
    def test_risk_level_critical(self):
        finding = Finding(
            rule_id="TEST-001",
            rule_name="Test",
            description="Test",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            location=Location("/test.py", 1, 0, ""),
        )
        pf = PrioritizedFinding(
            finding=finding,
            priority_score=85,
            owasp_weight=10,
            cwe_multiplier=1.5,
            severity_score=100,
        )
        assert pf.risk_level == "CRITICAL"

    def test_risk_level_high(self):
        finding = Finding(
            rule_id="TEST-001",
            rule_name="Test",
            description="Test",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            location=Location("/test.py", 1, 0, ""),
        )
        pf = PrioritizedFinding(
            finding=finding,
            priority_score=65,
            owasp_weight=8,
            cwe_multiplier=1.2,
            severity_score=75,
        )
        assert pf.risk_level == "HIGH"

    def test_risk_level_low(self):
        finding = Finding(
            rule_id="TEST-001",
            rule_name="Test",
            description="Test",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            location=Location("/test.py", 1, 0, ""),
        )
        pf = PrioritizedFinding(
            finding=finding,
            priority_score=15,
            owasp_weight=4,
            cwe_multiplier=1.0,
            severity_score=25,
        )
        assert pf.risk_level == "INFO"
