# SentinelScan

A multi-layered static application security testing (SAST) tool for source code analysis. Combines pattern-based detection, AST parsing, inter-procedural dataflow analysis, framework-specific analyzers, and optional LLM-powered vulnerability assessment.

Built for security engineers, AppSec teams, and developers integrating security into CI/CD pipelines.

---

## Table of Contents

- [Architecture](#architecture)
- [Detection Capabilities](#detection-capabilities)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Analysis Engines](#analysis-engines)
- [Rule System](#rule-system)
- [Output Formats](#output-formats)
- [Git Hooks Integration](#git-hooks-integration)
- [CI/CD Integration](#cicd-integration)
- [LLM-Enhanced Analysis](#llm-enhanced-analysis)
- [Python API](#python-api)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Performance](#performance)
- [Limitations](#limitations)

---

## Architecture

```
                          ┌──────────────────────────────────────────────────┐
                          │              SENTINELSCAN v0.5.0           │
                          ├──────────────────────────────────────────────────┤
                          │                                                  │
  Input Sources           │   Analysis Pipeline                              │   Output
  ─────────────           │   ─────────────────                              │   ──────
                          │                                                  │
  CLI ──────────┐         │   ┌─────────────┐  ┌──────────────────┐         │   ┌───────────┐
  Git Hooks ────┤         │   │ Rule Engine  │  │ Context Analyzer │         │   │ Console   │
  CI/CD ────────┤────────►│   │ (239 rules)  │  │ (FP filtering)   │────────►│   │ JSON      │
  Python API ───┤         │   └──────┬───────┘  └────────┬─────────┘         │   │ CSV       │
  GitHub Actions┘         │          │                   │                   │   │ SARIF     │
                          │   ┌──────▼───────┐  ┌────────▼─────────┐         │   │ HTML      │
                          │   │ AST Analyzer  │  │ Dataflow Tracker │         │   └───────────┘
                          │   │ (tree-sitter) │  │ (taint analysis) │         │
                          │   └──────┬───────┘  └────────┬─────────┘         │
                          │          │                   │                   │
                          │   ┌──────▼───────┐  ┌────────▼─────────┐         │
                          │   │ Spring       │  │ MyBatis          │         │
                          │   │ Analyzer     │  │ Analyzer         │         │
                          │   └──────┬───────┘  └────────┬─────────┘         │
                          │          │                   │                   │
                          │   ┌──────▼───────────────────▼─────────┐         │
                          │   │      LLM Analyzer (optional)       │         │
                          │   │      Claude API integration        │         │
                          │   └────────────────────────────────────┘         │
                          └──────────────────────────────────────────────────┘
```

---

## Detection Capabilities

### Vulnerability Classes

| Category | CWE Coverage | Detection Method |
|----------|-------------|-----------------|
| SQL Injection | CWE-89 | Pattern + AST taint tracking + MyBatis `${}` interpolation |
| Command Injection | CWE-78 | Pattern + AST source-to-sink analysis |
| Path Traversal | CWE-22 | Pattern + dataflow tracking |
| XSS | CWE-79 | Pattern + AST analysis |
| SSRF | CWE-918 | Pattern + dataflow tracking |
| Insecure Deserialization | CWE-502 | Pattern matching |
| Broken Access Control | CWE-862 | Spring Security config analysis |
| Cryptographic Failures | CWE-327, CWE-328 | Weak algorithm detection |
| Security Misconfiguration | CWE-16 | Framework config analysis |
| IDOR | CWE-639 | Pattern matching on direct object references |
| Sensitive Data in Logs | CWE-532 | Logging pattern analysis |
| Hardcoded Secrets | CWE-798 | Pattern + entropy validation |
| CSRF | CWE-352 | Spring Security CSRF config analysis |
| CORS Misconfiguration | CWE-942 | Permissive origin detection |

### OWASP Top 10 Mapping

Full rule coverage across all OWASP 2021 categories:

- **A01** - Broken Access Control (path traversal, IDOR, missing auth)
- **A02** - Cryptographic Failures (weak ciphers, insecure random, plaintext storage)
- **A03** - Injection (SQL, command, LDAP, XPath, template injection)
- **A04** - Insecure Design (race conditions, business logic)
- **A05** - Security Misconfiguration (debug mode, default credentials, permissive configs)
- **A06** - Vulnerable Components (dependency patterns)
- **A07** - Authentication Failures (weak password policies, session issues)
- **A08** - Software Integrity Failures (insecure deserialization, code signing)
- **A09** - Logging Failures (sensitive data in logs, insufficient logging)
- **A10** - SSRF (server-side request forgery patterns)

### Language Support

| Language | Pattern Rules | AST Analysis | Dataflow | Framework-Specific |
|----------|:---:|:---:|:---:|:---:|
| Java | Yes | Yes | Yes | Spring, MyBatis |
| Python | Yes | Yes | Yes | Django |
| JavaScript/TypeScript | Yes | Yes | No | Express |
| PHP | Yes | No | No | Laravel |
| Go | Yes | No | No | - |
| C# | Yes | No | No | - |
| Ruby | Yes | No | No | - |
| XML (config files) | Yes | - | - | MyBatis mappers |
| YAML/Properties | Yes | - | - | Spring config |

---

## Installation

### Prerequisites

- Python 3.8+
- pip

### Option 1: Quick Install Script

```bash
git clone <repo-url> sentinelscan
cd sentinelscan
chmod +x install.sh
./install.sh
```

This creates a virtualenv at `~/.sentinelscan/`, installs dependencies, and adds `sentinelscan` to your PATH.

### Option 2: Manual Install

```bash
git clone <repo-url> sentinelscan
cd sentinelscan
python3 -m venv venv
source venv/bin/activate
pip install pyyaml tree-sitter tree-sitter-java tree-sitter-python tree-sitter-javascript
```

### Verify Installation

```bash
python -m scanengine.cli --version
python -m scanengine.cli --list-rules -r rules
```

---

## Quick Start

### Scan a codebase

```bash
# Basic scan (all severities, console output)
python -m scanengine.cli /path/to/code -r rules

# Filter to high+ severity, Java only
python -m scanengine.cli /path/to/code -r rules -s high -l java

# JSON output to file
python -m scanengine.cli /path/to/code -r rules -f json -o results.json

# SARIF output for GitHub Security tab
python -m scanengine.cli /path/to/code -r rules -f sarif -o results.sarif

# Skip test files, include verbose logging
python -m scanengine.cli /path/to/code -r rules --skip-test-files -v

# Exclude directories
python -m scanengine.cli /path/to/code -r rules --exclude "*/test/*" "*/mock/*"
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | Findings present (medium or below) |
| 2 | High severity findings or scan errors |
| 3 | Critical severity findings |

---

## CLI Reference

### `sentinelscan` (Main Scanner)

```
usage: sentinelscan [-h] [-o OUTPUT] [-f {console,csv,json,sarif}]
                         [--no-color] [-l LANGUAGE] [-s SEVERITY]
                         [--tags TAGS] [--exclude PATTERN]
                         [-r RULES_DIR] [--list-rules]
                         [--no-context-analysis] [--no-ast-analysis]
                         [--skip-test-files] [--include-vendor]
                         [-v] [--debug] [-j JOBS]
                         target
```

| Flag | Description |
|------|-------------|
| `target` | Path to source code directory or file |
| `-o, --output FILE` | Output file path (default: stdout) |
| `-f, --format FORMAT` | Output format: `console`, `csv`, `json`, `sarif` |
| `-l, --language LANG` | Filter by language (repeatable): `java`, `python`, `javascript`, etc. |
| `-s, --severity LEVEL` | Minimum severity: `critical`, `high`, `medium`, `low`, `info` |
| `--tags TAG [TAG...]` | Filter by rule tags: `spring`, `sql-injection`, `secrets`, etc. |
| `--exclude PATTERN` | Exclude paths matching glob patterns |
| `-r, --rules-dir DIR` | Path to rules directory |
| `--list-rules` | List all loaded rules and exit |
| `--skip-test-files` | Skip test file scanning |
| `--include-vendor` | Include vendor/third-party files (excluded by default) |
| `--no-context-analysis` | Disable context-aware false positive filtering |
| `--no-ast-analysis` | Disable AST-based vulnerability detection |
| `-j, --jobs N` | Parallel worker threads (default: 4) |
| `-v, --verbose` | Verbose output |
| `--debug` | Debug logging |

### `llm_analyze` (LLM-Enhanced Analysis)

```bash
# Requires ANTHROPIC_API_KEY environment variable
export ANTHROPIC_API_KEY='sk-ant-...'

python -m scanengine.llm_analyze /path/to/code \
  --rules-dir rules \
  --explain \
  --remediate \
  --check-fp \
  --min-severity high \
  --max-findings 10 \
  --output llm-results.json
```

| Flag | Description |
|------|-------------|
| `target` | Path to scan |
| `--rules-dir DIR` | Rules directory |
| `--min-severity LEVEL` | Minimum severity for LLM analysis (default: `medium`) |
| `--max-findings N` | Cap on findings sent to LLM (default: 20, controls API cost) |
| `--explain` | Generate vulnerability explanations |
| `--remediate` | Generate code fix suggestions |
| `--check-fp` | Run false positive analysis |
| `-o, --output FILE` | Save enhanced results as JSON |
| `-v, --verbose` | Debug logging |

### `hooks installer` (Git Hooks)

```bash
# Install hooks in current repo
python -m scanengine.hooks.installer install

# Custom thresholds
python -m scanengine.hooks.installer install \
  --commit-threshold high \
  --push-threshold medium \
  --rules-dir /path/to/rules

# Uninstall
python -m scanengine.hooks.installer uninstall
```

---

## Analysis Engines

### 1. Pattern Matching Engine

Regex-based detection using 239 YAML-defined rules. Supports context patterns (must-match + must-not-match), language-scoped patterns, and multiline matching.

### 2. AST Analyzer (tree-sitter)

Parses source code into abstract syntax trees for structural analysis:
- **Taint tracking** - Traces user input (sources) to dangerous operations (sinks)
- **Source identification** - `getParameter()`, `request.body`, `input()`, `sys.argv`, etc.
- **Sink identification** - `executeQuery()`, `exec()`, `Runtime.exec()`, `open()`, etc.
- **Supports** - Java, Python, JavaScript

### 3. Dataflow Analyzer

Inter-procedural taint analysis:
- Builds call graphs across files
- Tracks data flow from HTTP parameters through method calls to SQL queries/file operations
- Detects vulnerabilities that span multiple methods and classes

### 4. Spring Analyzer

Framework-aware analysis for Spring Boot/Spring Security:
- Detects `permitAll()` misconfigurations
- CSRF and CORS misconfiguration
- Endpoint authentication gaps
- `@Query` annotation SQL injection
- Actuator exposure

### 5. MyBatis Analyzer

XML mapper-specific SQL injection detection:
- Detects `${param}` string interpolation vs safe `#{param}` parameterization
- Analyzes `<if>`, `<foreach>`, `<choose>` dynamic SQL constructs
- LIKE clause injection patterns
- ORDER BY injection through `${}` in sort clauses

### 6. Context Analyzer (False Positive Reduction)

Reduces noise by understanding code context:
- Identifies test files, mock data, vendor code, generated code
- Entropy-based secret validation (filters low-entropy "secrets" like `password=test`)
- Framework detection adjusts rule applicability
- Confidence scoring based on surrounding code context

### 7. LLM Analyzer (Claude API)

AI-powered analysis layer (requires Anthropic API key):
- **Explanation** - Plain-language vulnerability breakdown, attack vectors, impact assessment
- **False positive validation** - AI verdict on whether finding is genuine
- **Remediation** - Concrete code fix suggestions with alternatives
- Built-in response caching (memory + disk) to minimize API costs
- Automatic retries with exponential backoff
- 8 security-focused prompt templates

---

## Rule System

### Structure

Rules are defined in YAML files organized by category:

```
rules/
├── owasp/                  # OWASP Top 10 categories
│   ├── a01_broken_access_control.yaml
│   ├── a02_cryptographic_failures.yaml
│   ├── a04_insecure_design.yaml
│   ├── a05_injection.yaml
│   ├── a05_security_misconfiguration.yaml
│   ├── a06_vulnerable_components.yaml
│   ├── a07_auth_failures.yaml
│   ├── a08_integrity_failures.yaml
│   ├── a09_logging_failures.yaml
│   └── a10_ssrf.yaml
├── frameworks/             # Framework-specific
│   ├── spring/spring_security.yaml
│   ├── django/django_security.yaml
│   ├── express/express_security.yaml
│   └── laravel/laravel_security.yaml
├── secrets/                # Secret/credential detection
│   └── secret_patterns.yaml
├── phase1/                 # Core rules
│   ├── java_spring_core.yaml
│   └── secrets_core.yaml
└── phase2/                 # Extended rules
    ├── owasp_access_control.yaml
    ├── owasp_crypto.yaml
    ├── owasp_injection.yaml
    ├── owasp_logging.yaml
    └── owasp_ssrf.yaml
```

### Rule Statistics

| Severity | Count |
|----------|-------|
| Critical | 77 |
| High | 88 |
| Medium | 60 |
| Low | 9 |
| Info | 5 |
| **Total** | **239** |

### Rule Format

```yaml
- id: SQLI-001
  name: SQL Injection via String Concatenation
  description: SQL query built with string concatenation using user input
  severity: critical
  confidence: high
  cwe: CWE-89
  owasp: A03
  languages:
    - java
  tags:
    - sql-injection
    - injection
  patterns:
    - pattern: '\"SELECT.*\"\s*\+\s*\w+'
      description: String concatenation in SQL query
    - pattern: 'createQuery\s*\(\s*"[^"]*"\s*\+\s*'
      description: JPA createQuery with concatenation
  remediation:
    description: Use parameterized queries or prepared statements
    code_examples:
      java: |
        // Bad
        String query = "SELECT * FROM users WHERE id = " + userId;
        // Good
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, userId);
  references:
    - https://cwe.mitre.org/data/definitions/89.html
    - https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
```

### Writing Custom Rules

1. Create a YAML file in the `rules/` directory (or any subdirectory)
2. Define rules following the schema above
3. Use `--rules-dir` to point to your rules directory
4. Use `--list-rules` to verify rules are loaded

Key fields:
- **`patterns[].pattern`** - Python regex pattern
- **`patterns[].missing`** - Negative pattern (finding suppressed if this matches on the same line)
- **`patterns[].context`** - Context pattern that must appear within 5 lines
- **`languages`** - Restrict to specific file types
- **`file_patterns`** - Restrict to specific filenames (glob syntax)

---

## Output Formats

### Console (default)

Color-coded terminal output with severity indicators, file locations, and snippets.

### JSON (`-f json`)

```json
{
  "target_path": "/path/to/code",
  "files_scanned": 1075,
  "rules_applied": 180,
  "scan_duration_seconds": 15.93,
  "findings": [
    {
      "rule_id": "SQLI-001",
      "rule_name": "SQL Injection via String Concatenation",
      "severity": "critical",
      "confidence": "high",
      "file_path": "src/main/java/com/example/UserDAO.java",
      "line_number": 42,
      "snippet": "String query = \"SELECT * FROM users WHERE id = \" + userId;",
      "cwe": "CWE-89",
      "owasp": "A03",
      "remediation": "Use parameterized queries"
    }
  ]
}
```

### SARIF (`-f sarif`)

Standard SARIF 2.1.0 output compatible with:
- GitHub Code Scanning / Security tab
- GitLab SAST reports
- Azure DevOps
- Any SARIF-compatible viewer

Upload to GitHub:
```bash
# Generate SARIF
python -m scanengine.cli /path/to/code -r rules -f sarif -o results.sarif

# Upload via gh CLI
gh api /repos/{owner}/{repo}/code-scanning/sarifs \
  -X POST \
  -F sarif=@results.sarif
```

### HTML (Python API)

Executive-style HTML report with:
- Severity distribution doughnut chart
- Top vulnerability categories bar chart
- Interactive severity filtering
- Expandable finding details with code snippets
- Dark theme, responsive layout

```python
from scanengine import create_scanner, HTMLReporter

scanner = create_scanner(rules_dir="rules", severity_min="medium")
result = scanner.scan("/path/to/code")

reporter = HTMLReporter()
reporter.write(result, "report.html", title="Q1 Security Audit", base_path="/path/to/code")
```

### CSV (`-f csv`)

Flat CSV output for spreadsheet analysis and data processing.

---

## Git Hooks Integration

### Install Pre-commit and Pre-push Hooks

```bash
# Install both hooks with defaults
python -m scanengine.hooks.installer install

# Install with custom thresholds
python -m scanengine.hooks.installer install \
  --commit-threshold high \
  --push-threshold critical \
  --rules-dir /path/to/rules

# Install only pre-commit
python -m scanengine.hooks.installer install --no-pre-push

# Uninstall (restores previous hooks if they existed)
python -m scanengine.hooks.installer uninstall
```

### Pre-commit Hook Behavior

- Scans **staged files only** for fast feedback
- Blocks commit if findings meet or exceed the severity threshold (default: `critical`)
- Shows colored severity summary in terminal
- Bypass with `git commit --no-verify` (for emergencies)

### Pre-push Hook Behavior

- Performs **full branch scan**
- Compares against the base branch (`main`/`master`)
- Only blocks on **new findings** introduced in the branch
- Shows diff report with findings by severity
- Bypass with `git push --no-verify`

### Environment Variable Overrides

| Variable | Purpose | Default |
|----------|---------|---------|
| `SECURITY_SCAN_THRESHOLD` | Pre-commit severity threshold | `critical` |
| `SECURITY_PUSH_THRESHOLD` | Pre-push severity threshold | `high` |
| `SECURITY_RULES_DIR` | Rules directory path | auto-detect |
| `SECURITY_COMPARE_BRANCH` | Base branch for comparison | `main`/`master` |

---

## CI/CD Integration

### GitHub Actions

A ready-to-use workflow is included at `.github/workflows/security-scan.yml`. It:

1. Runs on push to `main`/`develop` and on pull requests
2. Scans the repository with configurable severity threshold
3. Uploads SARIF results to the GitHub Security tab
4. Posts a findings summary comment on PRs
5. Fails the pipeline on critical findings
6. Optionally runs LLM analysis for critical issues (requires `ANTHROPIC_API_KEY` secret)

**Setup:**
1. Copy `.github/workflows/security-scan.yml` to your repository
2. Add the `rules/` directory to your repository (or configure a shared rules path)
3. (Optional) Add `ANTHROPIC_API_KEY` as a repository secret for LLM analysis

### GitLab CI

```yaml
security-scan:
  stage: test
  image: python:3.10
  before_script:
    - pip install pyyaml tree-sitter tree-sitter-java tree-sitter-python
  script:
    - python -m scanengine.cli . -r rules -f sarif -o gl-sast-report.sarif -s medium
    - python -m scanengine.cli . -r rules -f json -o gl-sast-report.json -s medium
  artifacts:
    reports:
      sast: gl-sast-report.sarif
    paths:
      - gl-sast-report.json
    when: always
  allow_failure: false
```

### Jenkins

```groovy
pipeline {
    agent any

    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    python -m scanengine.cli . \
                      -r rules \
                      -f sarif \
                      -o security-results.sarif \
                      -s high
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'security-results.sarif'
                    recordIssues tool: sarif(pattern: 'security-results.sarif')
                }
            }
        }
    }
}
```

### Azure DevOps

```yaml
- task: PythonScript@0
  inputs:
    scriptSource: 'inline'
    script: |
      import subprocess
      subprocess.run([
        'python', '-m', 'scanengine.cli', '.',
        '-r', 'rules',
        '-f', 'sarif',
        '-o', '$(Build.ArtifactStagingDirectory)/results.sarif',
        '-s', 'medium'
      ], check=True)
- task: PublishBuildArtifacts@1
  inputs:
    PathtoPublish: '$(Build.ArtifactStagingDirectory)/results.sarif'
    ArtifactName: 'SecurityScanResults'
```

---

## LLM-Enhanced Analysis

### Overview

The LLM module uses the Claude API to provide deeper analysis on top of static findings. This is optional and requires an Anthropic API key.

### What It Provides

| Feature | Description |
|---------|-------------|
| **Vulnerability Explanation** | Plain-language summary, attack vector breakdown, impact assessment (CIA triad), exploitability rating |
| **False Positive Analysis** | AI verdict (`true_positive` / `false_positive` / `uncertain`) with evidence and reasoning |
| **Remediation Guidance** | Primary fix with code example, alternative approaches, prevention practices, testing recommendations |

### Cost Control

- `--max-findings N` caps the number of findings sent to the API (default: 20)
- Built-in response caching (same finding + same code = cache hit, no API call)
- Disk-based cache persists across runs
- Automatic retry with exponential backoff on rate limits

### Usage

```bash
export ANTHROPIC_API_KEY='sk-ant-...'

# Full analysis on top 5 critical findings
python -m scanengine.llm_analyze /path/to/code \
  --rules-dir rules \
  --explain \
  --remediate \
  --check-fp \
  --min-severity critical \
  --max-findings 5 \
  --output enhanced-report.json
```

### Python API

```python
from scanengine import create_scanner, create_llm_analyzer, create_context_assembler

scanner = create_scanner(rules_dir="rules")
result = scanner.scan("/path/to/code")

analyzer = create_llm_analyzer()
analyzer.set_content_cache(scanner._content_cache)

for finding in result.findings[:5]:
    enhanced = analyzer.enhance_finding(
        finding,
        explain=True,
        remediate=True,
        check_false_positive=True,
    )
    print(enhanced.explanation)
    print(enhanced.remediation)
    print(enhanced.false_positive_analysis)
```

---

## Python API

### Basic Scanning

```python
from scanengine import create_scanner

# Create scanner with all engines enabled
scanner = create_scanner(
    rules_dir="rules",
    languages=["java", "python"],       # Filter rules by language
    severity_min="medium",              # Minimum severity to report
    enable_context_analysis=True,       # False positive filtering
    enable_ast_analysis=True,           # AST-based taint tracking
    enable_dataflow_analysis=True,      # Inter-procedural dataflow
    filter_test_files=True,             # Skip test files
    filter_vendor_files=True,           # Skip vendor/third-party code
)

result = scanner.scan("/path/to/code")

print(f"Files scanned: {result.files_scanned}")
print(f"Total findings: {len(result.findings)}")
print(f"Duration: {result.scan_duration_seconds:.2f}s")

# Access findings
for finding in result.findings:
    print(f"[{finding.severity.value}] {finding.rule_id}: {finding.rule_name}")
    print(f"  File: {finding.location.file_path}:{finding.location.line_number}")
    print(f"  CWE: {finding.cwe}")
    print(f"  Remediation: {finding.remediation}")

# Filter by severity
critical = result.get_findings_by_severity(Severity.CRITICAL)

# Summary dict
print(result.summary)
# {'critical': 5, 'high': 12, 'medium': 30, 'low': 8, 'info': 2}
```

### SARIF Generation

```python
from scanengine import create_scanner, SARIFReporter

scanner = create_scanner(rules_dir="rules", severity_min="medium")
result = scanner.scan("/path/to/code")

reporter = SARIFReporter(tool_name="My Security Scanner", tool_version="1.0.0")

# Write to file
reporter.write(result, "output.sarif", base_path="/path/to/code")

# Get as dict
sarif_dict = reporter.generate(result, base_path="/path/to/code")

# Get as JSON string
sarif_json = reporter.to_json(result, base_path="/path/to/code")
```

### HTML Report Generation

```python
from scanengine import create_scanner, HTMLReporter

scanner = create_scanner(rules_dir="rules")
result = scanner.scan("/path/to/code")

reporter = HTMLReporter(version="1.0.0")
reporter.write(result, "report.html", title="Security Audit Report", base_path="/path/to/code")
```

### Git Hooks (Programmatic)

```python
from scanengine import install_hooks, uninstall_hooks

# Install hooks in a repository
success, message = install_hooks(
    repo_path="/path/to/repo",
    pre_commit=True,
    pre_push=True,
    commit_threshold="high",
    push_threshold="critical",
    rules_dir="/path/to/rules",
)
print(message)

# Uninstall
success, message = uninstall_hooks(repo_path="/path/to/repo")
```

---

## Configuration

### Severity Levels

| Level | Priority | Meaning |
|-------|----------|---------|
| `critical` | 5 | Exploitable vulnerability, immediate risk |
| `high` | 4 | Significant vulnerability, should fix before release |
| `medium` | 3 | Potential vulnerability, context-dependent |
| `low` | 2 | Code quality / defense-in-depth concern |
| `info` | 1 | Informational observation |

### Confidence Levels

| Level | Meaning |
|-------|---------|
| `high` | Strong pattern match, AST-confirmed, or framework-specific detection |
| `medium` | Pattern match with some contextual uncertainty |
| `low` | Heuristic match, may require manual review |

### Scan Behavior

| Setting | Default | Effect |
|---------|---------|--------|
| Max file size | 10 MB | Files larger than this are skipped |
| Parallel workers | 4 | Threads for concurrent file scanning |
| Test file filtering | Off | When on, skips `*Test.java`, `*_test.py`, `*.spec.js`, etc. |
| Vendor file filtering | On | Skips `vendor/`, `node_modules/`, etc. |
| Context analysis | On | Reduces false positives via code context |
| AST analysis | On | Enables tree-sitter based taint tracking |
| Dataflow analysis | On | Enables inter-procedural taint analysis |

### Automatically Skipped Directories

```
.git, .svn, node_modules, __pycache__, .idea, .vscode,
target, build, dist, out, vendor, venv, .venv, .gradle, .mvn, bin, obj
```

---

## Project Structure

```
scanengine/
├── __init__.py              # Package exports (v0.5.0)
├── __main__.py              # python -m entry point
├── cli.py                   # Command-line interface
├── scanner.py               # Scan orchestrator
├── models.py                # Finding, Rule, ScanResult, Severity, etc.
├── rule_loader.py           # YAML rule parser
├── pattern_matcher.py       # Regex pattern matching + secret detection
├── context_analyzer.py      # Context-aware FP filtering, entropy validation
├── ast_analyzer.py          # Tree-sitter AST parsing & taint tracking
├── call_graph.py            # Inter-procedural call graph builder
├── dataflow_analyzer.py     # Source-to-sink taint analysis
├── spring_analyzer.py       # Spring Security / Spring Boot analysis
├── mybatis_analyzer.py      # MyBatis XML mapper SQL injection
├── reporters.py             # Console, CSV, JSON reporters
├── llm_analyze.py           # LLM analysis CLI entry point
├── hooks/                   # Git hooks integration
│   ├── __init__.py
│   ├── installer.py         # Install/uninstall git hooks
│   ├── pre_commit.py        # Pre-commit scan (staged files)
│   └── pre_push.py          # Pre-push scan (branch comparison)
├── llm/                     # LLM integration module
│   ├── __init__.py
│   ├── client.py            # Claude API client (caching, retries)
│   ├── prompts.py           # 8 security-focused prompt templates
│   ├── context.py           # Code context assembler for LLM
│   └── analyzer.py          # LLM security analyzer
└── reporters/               # Extended reporters
    ├── __init__.py
    ├── sarif.py              # SARIF 2.1.0 output
    └── html.py               # HTML executive report

rules/
├── owasp/                   # 10 OWASP category rule files
├── frameworks/              # Spring, Django, Express, Laravel
├── secrets/                 # Secret/credential detection
├── phase1/                  # Core detection rules
└── phase2/                  # Extended detection rules

.github/
└── workflows/
    └── security-scan.yml    # GitHub Actions workflow
```

---

## Performance

Benchmarked on a Spring Boot codebase (1,075 files):

| Metric | Value |
|--------|-------|
| Files scanned | 1,075 |
| Scan duration | ~16 seconds |
| Total findings | 236 (medium+ severity) |
| Peak memory | ~200 MB |
| Rules loaded | 180+ (after language filtering) |

Parallel scanning with 4 threads. Performance scales linearly with file count.

---

## Limitations

- **Not a replacement for DAST** - This is static analysis only. It does not execute code or interact with running applications.
- **No dependency/SCA scanning** - Does not analyze `pom.xml`, `package.json`, etc. for known vulnerable dependencies. Use tools like Dependabot, Snyk, or OWASP Dependency-Check alongside this tool.
- **No Docker/infrastructure analysis** - Does not analyze Dockerfiles, Kubernetes manifests, or Terraform configs for security issues.
- **Business logic flaws** - Static analysis cannot reliably detect authorization bypass, workflow abuse, or other business logic vulnerabilities (the LLM module can provide hints but not guarantees).
- **Absence-of-control patterns** - Cannot detect missing security controls (e.g., "there should be rate limiting here") without explicit rules.
- **AST support** - Tree-sitter analysis is currently limited to Java, Python, and JavaScript. Other languages use pattern matching only.
- **LLM costs** - The LLM module calls the Claude API. Use `--max-findings` to control costs. Caching reduces repeat analysis costs.

---

## License

Internal use. See LICENSE file for details.

---

*Version 0.5.0 | Built for security engineers, by security engineers.*
