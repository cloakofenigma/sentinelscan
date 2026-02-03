"""
HTML Report Generator for SentinelScan

Generates executive-friendly HTML reports with charts and summaries.
"""

import html
import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path
from collections import Counter

from ..models import Finding, ScanResult, Severity
from .impact import get_impact


HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {title}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #28a745;
            --info: #17a2b8;
            --bg-dark: #1a1a2e;
            --bg-card: #16213e;
            --text-primary: #eee;
            --text-secondary: #aaa;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            line-height: 1.6;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}

        header {{
            background: linear-gradient(135deg, #0f3460 0%, #16213e 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}

        header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
        }}

        header .meta {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .summary-card {{
            background: var(--bg-card);
            padding: 25px;
            border-radius: 10px;
            text-align: center;
        }}

        .summary-card.critical {{ border-left: 4px solid var(--critical); }}
        .summary-card.high {{ border-left: 4px solid var(--high); }}
        .summary-card.medium {{ border-left: 4px solid var(--medium); }}
        .summary-card.low {{ border-left: 4px solid var(--low); }}
        .summary-card.total {{ border-left: 4px solid var(--info); }}

        .summary-card .number {{
            font-size: 3rem;
            font-weight: bold;
        }}

        .summary-card .label {{
            color: var(--text-secondary);
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 1px;
        }}

        .charts {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-bottom: 30px;
        }}

        .chart-card {{
            background: var(--bg-card);
            padding: 25px;
            border-radius: 10px;
        }}

        .chart-card h3 {{
            margin-bottom: 20px;
            color: var(--text-secondary);
        }}

        .findings-section {{
            background: var(--bg-card);
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 30px;
        }}

        .findings-section h2 {{
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .severity-badge.critical {{ background: var(--critical); }}
        .severity-badge.high {{ background: var(--high); color: #000; }}
        .severity-badge.medium {{ background: var(--medium); color: #000; }}
        .severity-badge.low {{ background: var(--low); }}

        .finding {{
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 10px;
        }}

        .finding-title {{
            font-weight: 600;
            font-size: 1.1rem;
        }}

        .finding-location {{
            color: var(--info);
            font-family: monospace;
            font-size: 0.9rem;
        }}

        .finding-description {{
            color: var(--text-secondary);
            margin-bottom: 10px;
        }}

        .finding-meta {{
            display: flex;
            gap: 15px;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}

        .finding-meta span {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}

        .finding-details {{
            margin-top: 15px;
            display: grid;
            gap: 12px;
        }}

        .finding-detail-block {{
            background: rgba(0,0,0,0.2);
            border-radius: 6px;
            padding: 14px 16px;
            border-left: 3px solid transparent;
        }}

        .finding-detail-block.description {{
            border-left-color: var(--info);
        }}

        .finding-detail-block.impact {{
            border-left-color: var(--high);
        }}

        .finding-detail-block.mitigation {{
            border-left-color: var(--low);
        }}

        .finding-detail-label {{
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            margin-bottom: 6px;
        }}

        .finding-detail-block.description .finding-detail-label {{
            color: var(--info);
        }}

        .finding-detail-block.impact .finding-detail-label {{
            color: var(--high);
        }}

        .finding-detail-block.mitigation .finding-detail-label {{
            color: var(--low);
        }}

        .finding-detail-text {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            line-height: 1.6;
        }}

        .code-snippet {{
            background: #0d1117;
            border-radius: 6px;
            padding: 15px;
            margin-top: 10px;
            overflow-x: auto;
            font-family: 'Fira Code', 'Monaco', monospace;
            font-size: 0.85rem;
            line-height: 1.5;
        }}

        .filters {{
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }}

        .filter-btn {{
            padding: 8px 16px;
            border: none;
            border-radius: 20px;
            cursor: pointer;
            background: rgba(255,255,255,0.1);
            color: var(--text-primary);
            transition: all 0.2s;
        }}

        .filter-btn:hover, .filter-btn.active {{
            background: var(--info);
        }}

        footer {{
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.85rem;
        }}

        @media (max-width: 768px) {{
            .charts {{
                grid-template-columns: 1fr;
            }}

            header h1 {{
                font-size: 1.8rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Security Scan Report</h1>
            <div class="meta">
                <p><strong>Target:</strong> {target_path}</p>
                <p><strong>Scan Date:</strong> {scan_date}</p>
                <p><strong>Files Scanned:</strong> {files_scanned} | <strong>Duration:</strong> {duration}</p>
            </div>
        </header>

        <div class="summary-grid">
            <div class="summary-card total">
                <div class="number">{total_findings}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="summary-card critical">
                <div class="number">{critical_count}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="number">{high_count}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="number">{medium_count}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="number">{low_count}</div>
                <div class="label">Low</div>
            </div>
        </div>

        <div class="charts">
            <div class="chart-card">
                <h3>Findings by Severity</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>Top Vulnerability Categories</h3>
                <canvas id="categoryChart"></canvas>
            </div>
        </div>

        <div class="findings-section">
            <h2>Detailed Findings</h2>

            <div class="filters">
                <button class="filter-btn active" onclick="filterFindings('all')">All</button>
                <button class="filter-btn" onclick="filterFindings('critical')">Critical</button>
                <button class="filter-btn" onclick="filterFindings('high')">High</button>
                <button class="filter-btn" onclick="filterFindings('medium')">Medium</button>
                <button class="filter-btn" onclick="filterFindings('low')">Low</button>
            </div>

            <div id="findings-list">
                {findings_html}
            </div>
        </div>

        <footer>
            <p>Generated by SentinelScan v{version}</p>
            <p>Report generated on {generation_time}</p>
        </footer>
    </div>

    <script>
        // Severity Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{
                    data: [{critical_count}, {high_count}, {medium_count}, {low_count}],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{ color: '#eee' }}
                    }}
                }}
            }}
        }});

        // Category Chart
        const categoryCtx = document.getElementById('categoryChart').getContext('2d');
        new Chart(categoryCtx, {{
            type: 'bar',
            data: {{
                labels: {category_labels},
                datasets: [{{
                    label: 'Findings',
                    data: {category_data},
                    backgroundColor: '#17a2b8'
                }}]
            }},
            options: {{
                responsive: true,
                indexAxis: 'y',
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    x: {{
                        ticks: {{ color: '#aaa' }},
                        grid: {{ color: 'rgba(255,255,255,0.1)' }}
                    }},
                    y: {{
                        ticks: {{ color: '#aaa' }},
                        grid: {{ display: false }}
                    }}
                }}
            }}
        }});

        // Filter functionality
        function filterFindings(severity) {{
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            document.querySelectorAll('.finding').forEach(finding => {{
                if (severity === 'all' || finding.dataset.severity === severity) {{
                    finding.style.display = 'block';
                }} else {{
                    finding.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>'''


def escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return html.escape(str(text)) if text else ''


def format_finding_html(finding: Finding, base_path: Optional[str] = None) -> str:
    """Format a single finding as HTML."""
    file_path = finding.location.file_path
    if base_path and file_path.startswith(base_path):
        file_path = file_path[len(base_path):].lstrip('/')

    snippet_html = ""
    if finding.location.snippet:
        snippet_html = f'<pre class="code-snippet">{escape_html(finding.location.snippet[:500])}</pre>'

    cwe_html = f'<span>CWE: {escape_html(finding.cwe)}</span>' if finding.cwe else ''
    owasp_html = f'<span>OWASP: {escape_html(finding.owasp)}</span>' if finding.owasp else ''

    # Get impact and mitigation
    impact_text = escape_html(get_impact(finding))
    mitigation_text = escape_html(finding.remediation) if finding.remediation else 'Refer to the CWE/OWASP reference for recommended remediation steps.'

    return f'''
    <div class="finding" data-severity="{finding.severity.value}">
        <div class="finding-header">
            <div>
                <span class="severity-badge {finding.severity.value}">{finding.severity.value.upper()}</span>
                <span class="finding-title">{escape_html(finding.rule_name)}</span>
            </div>
            <span class="finding-location">{escape_html(file_path)}:{finding.location.line_number}</span>
        </div>
        <div class="finding-meta">
            <span>Rule: {escape_html(finding.rule_id)}</span>
            {cwe_html}
            {owasp_html}
            <span>Confidence: {escape_html(finding.confidence.value if hasattr(finding.confidence, 'value') else finding.confidence)}</span>
        </div>
        {snippet_html}
        <div class="finding-details">
            <div class="finding-detail-block description">
                <div class="finding-detail-label">Description</div>
                <div class="finding-detail-text">{escape_html(finding.description)}</div>
            </div>
            <div class="finding-detail-block impact">
                <div class="finding-detail-label">Impact</div>
                <div class="finding-detail-text">{impact_text}</div>
            </div>
            <div class="finding-detail-block mitigation">
                <div class="finding-detail-label">Mitigation</div>
                <div class="finding-detail-text">{mitigation_text}</div>
            </div>
        </div>
    </div>
    '''


def generate_html_report(
    scan_result: ScanResult,
    title: str = "Security Scan",
    base_path: Optional[str] = None,
    version: str = "0.5.0"
) -> str:
    """
    Generate HTML report from scan results.

    Args:
        scan_result: Scan results
        title: Report title
        base_path: Base path for relative paths
        version: Tool version

    Returns:
        HTML string
    """
    findings = scan_result.findings

    # Count by severity
    severity_counts = Counter(f.severity.value for f in findings)

    # Count by category (rule prefix)
    category_counts = Counter()
    for f in findings:
        category = f.rule_id.split('-')[0]
        category_counts[category] += 1

    # Get top 8 categories
    top_categories = category_counts.most_common(8)
    category_labels = json.dumps([c[0] for c in top_categories])
    category_data = json.dumps([c[1] for c in top_categories])

    # Sort findings by severity
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity.value, 4))

    # Generate findings HTML
    findings_html = '\n'.join(format_finding_html(f, base_path) for f in sorted_findings[:200])
    if len(findings) > 200:
        findings_html += f'<p style="text-align:center;color:#aaa;margin-top:20px;">... and {len(findings) - 200} more findings</p>'

    # Format duration
    duration = f"{scan_result.scan_duration:.2f}s" if hasattr(scan_result, 'scan_duration') else "N/A"

    # Generate report
    report = HTML_TEMPLATE.format(
        title=escape_html(title),
        target_path=escape_html(base_path or "Unknown"),
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        files_scanned=scan_result.files_scanned,
        duration=duration,
        total_findings=len(findings),
        critical_count=severity_counts.get('critical', 0),
        high_count=severity_counts.get('high', 0),
        medium_count=severity_counts.get('medium', 0),
        low_count=severity_counts.get('low', 0),
        findings_html=findings_html,
        category_labels=category_labels,
        category_data=category_data,
        version=version,
        generation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    )

    return report


def write_html_report(
    scan_result: ScanResult,
    output_path: str,
    title: str = "Security Scan",
    base_path: Optional[str] = None
) -> str:
    """Write HTML report to file."""
    report = generate_html_report(scan_result, title, base_path)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)

    return output_path


class HTMLReporter:
    """HTML reporter class."""

    def __init__(self, version: str = "0.5.0"):
        self.version = version

    def generate(
        self,
        scan_result: ScanResult,
        title: str = "Security Scan",
        base_path: Optional[str] = None
    ) -> str:
        """Generate HTML report."""
        return generate_html_report(scan_result, title, base_path, self.version)

    def write(
        self,
        scan_result: ScanResult,
        output_path: str,
        title: str = "Security Scan",
        base_path: Optional[str] = None
    ) -> str:
        """Write HTML report to file."""
        return write_html_report(scan_result, output_path, title, base_path)
