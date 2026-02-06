# SentinelScan Usage Guide

## Quick Start

### Basic Scan
```bash
# Scan a directory
python -m scanengine.cli /path/to/project

# Scan with output file
python -m scanengine.cli /path/to/project -o results.sarif

# Multiple output formats
python -m scanengine.cli /path/to/project -o results.sarif -o results.html -o results.xlsx
```

### Filtering Options
```bash
# Only critical and high severity
python -m scanengine.cli /path/to/project --severity high

# Filter by language
python -m scanengine.cli /path/to/project --language java,python

# Exclude test files
python -m scanengine.cli /path/to/project --exclude-tests

# Verbose output
python -m scanengine.cli /path/to/project -v
```

## Python API

### Basic Usage
```python
from scanengine.scanner import create_scanner

# Create scanner with default rules
scanner = create_scanner()

# Scan a project
result = scanner.scan("/path/to/project")

# Print findings
for finding in result.findings:
    print(f"{finding.severity.value}: {finding.rule_name}")
    print(f"  File: {finding.location.file_path}:{finding.location.line_number}")
    print(f"  {finding.description}")
```

### Advanced Configuration
```python
from scanengine.scanner import SecurityScanner
from scanengine.models import Severity
from pathlib import Path

# Create scanner with custom options
scanner = SecurityScanner(
    rules_dir=Path("custom_rules"),
    max_workers=8,
    enable_context_analysis=True,
    enable_ast_analysis=True,
    enable_dataflow_analysis=True,
    filter_test_files=True,
)

# Load rules with filters
scanner.load_rules(
    languages=["java", "python"],
    severity_min=Severity.MEDIUM,
)

# Run scan
result = scanner.scan("/path/to/project", exclude_patterns=["*generated*"])

# Access results
print(f"Files scanned: {result.files_scanned}")
print(f"Findings: {len(result.findings)}")
print(f"Duration: {result.scan_duration_seconds:.2f}s")

# Filter findings
critical = result.filter_by_severity(Severity.CRITICAL)
sql_injection = result.filter_by_cwe("CWE-89")
```

### Output Formats
```python
from scanengine.reporters.sarif import generate_sarif, write_sarif
from scanengine.reporters.html import generate_html_report, write_html_report
from scanengine.reporters.excel import generate_excel_report

# SARIF (for CI/CD integration)
sarif = generate_sarif(result)
write_sarif(result, "results.sarif")

# HTML (for review)
html = generate_html_report(result)
write_html_report(result, "results.html")

# Excel (for reporting)
generate_excel_report(result, "results.xlsx")
```

## Profiling

```python
from scanengine.profiling import ScanProfiler, profile, timed

# Method 1: Function decorator
@timed
def my_analysis():
    ...

# Method 2: Context manager
with profile("custom_operation"):
    do_work()

# Method 3: Full profiler
profiler = ScanProfiler()
profiler.start_scan("/path/to/project")

for file in files:
    with profiler.file_context(str(file)):
        analyze(file)

print(profiler.report())
```

## Custom Rules

Create YAML rule files in `rules/` directory:

```yaml
rules:
  - id: CUSTOM-001
    name: Custom SQL Injection
    description: Detects potential SQL injection
    severity: critical
    confidence: high
    cwe: CWE-89
    owasp: A03
    languages:
      - java
    patterns:
      - pattern: 'executeQuery\s*\([^)]*\+'
        language: java
    remediation:
      description: Use PreparedStatement with parameterized queries
      code_examples:
        java: |
          PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
          stmt.setString(1, userId);
```

## Suppressing Findings

Add `nosec` comments to suppress findings:

```java
// Suppress all rules on this line
String query = buildQuery(input); // nosec

// Suppress specific rule
String query = buildQuery(input); // nosec SQLI-001

// Multiple rules
String query = buildQuery(input); // nosec SQLI-001, CMD-001
```

## CI/CD Integration

### GitHub Actions
```yaml
- name: Security Scan
  run: |
    pip install sentinelscan
    python -m scanengine.cli . -o results.sarif --severity high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### GitLab CI
```yaml
security_scan:
  script:
    - pip install sentinelscan
    - python -m scanengine.cli . -o gl-sast-report.json --format gitlab
  artifacts:
    reports:
      sast: gl-sast-report.json
```

## Supported Languages & Frameworks

### Languages (15+)
- Java, Kotlin, Scala
- Python
- JavaScript, TypeScript
- Go
- Rust
- C#
- Ruby
- PHP
- Swift

### Frameworks (20+)
- Spring Boot, Spring Security
- Django, Flask
- React, Vue, Angular
- Express.js
- Ruby on Rails
- ASP.NET Core
- Gin (Go)
- Laravel (PHP)

### Infrastructure as Code
- Terraform
- Kubernetes manifests
- CloudFormation
- Dockerfile
