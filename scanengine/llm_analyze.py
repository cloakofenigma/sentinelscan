#!/usr/bin/env python3
"""
LLM-Enhanced Security Analysis Script
Usage: python -m scanengine.llm_analyze <target_path> [options]

This script runs the security scanner and then enhances findings with LLM analysis.
Requires ANTHROPIC_API_KEY environment variable to be set.
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from datetime import datetime

from .scanner import create_scanner
from .llm import create_llm_analyzer, create_context_assembler
from .models import Severity

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="Run security scan with LLM-enhanced analysis"
    )
    parser.add_argument("target", help="Path to scan")
    parser.add_argument("--rules-dir", help="Path to rules directory")
    parser.add_argument("--min-severity", default="medium",
                       choices=["critical", "high", "medium", "low", "info"],
                       help="Minimum severity to analyze with LLM")
    parser.add_argument("--max-findings", type=int, default=20,
                       help="Maximum findings to analyze with LLM (for cost control)")
    parser.add_argument("--explain", action="store_true",
                       help="Generate explanations for findings")
    parser.add_argument("--remediate", action="store_true",
                       help="Generate remediation suggestions")
    parser.add_argument("--check-fp", action="store_true",
                       help="Check for false positives")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Check for API key
    if not os.environ.get("ANTHROPIC_API_KEY"):
        logger.error("ANTHROPIC_API_KEY environment variable not set")
        logger.info("Set it with: export ANTHROPIC_API_KEY='your-key'")
        sys.exit(1)

    target_path = Path(args.target).resolve()
    if not target_path.exists():
        logger.error(f"Target path does not exist: {target_path}")
        sys.exit(1)

    print("=" * 70)
    print("LLM-ENHANCED SECURITY ANALYSIS")
    print(f"Target: {target_path}")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 70)

    # Step 1: Run the scanner
    print("\n[1/3] Running security scan...")
    scanner = create_scanner(
        rules_dir=args.rules_dir,
        severity_min="low",
        enable_dataflow_analysis=True,
    )

    result = scanner.scan(str(target_path))
    print(f"      Scanned {result.files_scanned} files")
    print(f"      Found {len(result.findings)} findings")

    # Step 2: Filter findings for LLM analysis
    severity_priority = {
        "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1
    }
    min_priority = severity_priority[args.min_severity]

    filtered = [f for f in result.findings
                if f.severity.priority >= min_priority]

    # Sort by severity and limit
    filtered.sort(key=lambda f: -f.severity.priority)
    to_analyze = filtered[:args.max_findings]

    print(f"\n[2/3] Preparing LLM analysis...")
    print(f"      Findings meeting criteria: {len(filtered)}")
    print(f"      Findings to analyze: {len(to_analyze)}")

    if not to_analyze:
        print("      No findings to analyze")
        return

    # Step 3: Run LLM analysis
    print(f"\n[3/3] Running LLM analysis...")

    analyzer = create_llm_analyzer()
    context_assembler = create_context_assembler(scanner._content_cache)
    analyzer.set_content_cache(scanner._content_cache)

    enhanced_findings = []
    for i, finding in enumerate(to_analyze):
        print(f"      Analyzing {i+1}/{len(to_analyze)}: {finding.rule_id}...", end="", flush=True)

        enhanced = analyzer.enhance_finding(
            finding,
            explain=args.explain,
            remediate=args.remediate,
            check_false_positive=args.check_fp,
        )
        enhanced_findings.append(enhanced)
        print(" done")

    # Results
    print("\n" + "=" * 70)
    print("ANALYSIS RESULTS")
    print("=" * 70)

    # Summary
    if args.check_fp:
        true_pos = len([f for f in enhanced_findings
                       if f.false_positive_analysis and
                       f.false_positive_analysis.get('verdict') == 'true_positive'])
        false_pos = len([f for f in enhanced_findings
                        if f.false_positive_analysis and
                        f.false_positive_analysis.get('verdict') == 'false_positive'])
        uncertain = len([f for f in enhanced_findings
                        if f.false_positive_analysis and
                        f.false_positive_analysis.get('verdict') == 'uncertain'])

        print(f"\nFalse Positive Analysis:")
        print(f"  True Positives: {true_pos}")
        print(f"  False Positives: {false_pos}")
        print(f"  Uncertain: {uncertain}")

    # Detailed results
    for ef in enhanced_findings:
        print(f"\n{'─' * 70}")
        print(f"[{ef.original.severity.value.upper()}] {ef.original.rule_id}: {ef.original.rule_name}")
        print(f"Location: {ef.original.location.file_path}:{ef.original.location.line_number}")

        if ef.explanation and 'summary' in ef.explanation:
            print(f"\nExplanation: {ef.explanation['summary']}")

        if ef.false_positive_analysis and 'verdict' in ef.false_positive_analysis:
            verdict = ef.false_positive_analysis['verdict']
            confidence = ef.false_positive_analysis.get('confidence', 'unknown')
            print(f"\nFP Analysis: {verdict} (confidence: {confidence})")
            if 'reasoning' in ef.false_positive_analysis:
                print(f"  Reasoning: {ef.false_positive_analysis['reasoning'][:200]}...")

        if ef.remediation and 'primary_fix' in ef.remediation:
            print(f"\nRemediation: {ef.remediation['primary_fix'].get('description', 'N/A')}")

    # LLM Stats
    stats = analyzer.get_stats()
    print(f"\n{'─' * 70}")
    print("LLM Usage Statistics:")
    print(f"  Total requests: {stats['total_requests']}")
    print(f"  Total tokens: {stats['total_tokens']}")
    print(f"  Cache hit rate: {stats['cache_hit_rate']}")

    # Save output
    if args.output:
        output_data = {
            'timestamp': datetime.now().isoformat(),
            'target': str(target_path),
            'scan_summary': result.summary,
            'llm_stats': stats,
            'enhanced_findings': [ef.to_dict() for ef in enhanced_findings],
        }

        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()
