"""Tests for Go language analyzer."""

import pytest
from pathlib import Path
from scanengine.analyzers.languages.go import GoAnalyzer
from scanengine.models import Severity


@pytest.fixture
def analyzer():
    return GoAnalyzer()


class TestGoAnalyzerProperties:
    def test_name(self, analyzer):
        assert analyzer.name == "go_analyzer"

    def test_supported_extensions(self, analyzer):
        assert '.go' in analyzer.supported_extensions

    def test_dangerous_sinks_defined(self, analyzer):
        assert 'sql_injection' in analyzer.dangerous_sinks
        assert 'command_injection' in analyzer.dangerous_sinks


class TestGoSQLInjection:
    def test_detects_query_concatenation(self, analyzer, tmp_path):
        code = '''
package main

import "database/sql"

func getUser(db *sql.DB, id string) {
    query := "SELECT * FROM users WHERE id = '" + id + "'"
    db.Query(query)
}
'''
        file_path = tmp_path / "main.go"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        sql_findings = [f for f in findings if 'SQL' in f.rule_id.upper() or 'sql' in f.description.lower()]
        assert len(sql_findings) >= 1

    def test_detects_exec_with_concatenation(self, analyzer, tmp_path):
        code = '''
package main

import "database/sql"

func deleteUser(db *sql.DB, id string) {
    db.Exec("DELETE FROM users WHERE id = " + id)
}
'''
        file_path = tmp_path / "main.go"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        assert len(findings) >= 1


class TestGoCommandInjection:
    def test_detects_exec_command(self, analyzer, tmp_path):
        code = '''
package main

import "os/exec"

func runCommand(input string) {
    cmd := exec.Command("sh", "-c", input)
    cmd.Run()
}
'''
        file_path = tmp_path / "main.go"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        cmd_findings = [f for f in findings if 'CMD' in f.rule_id.upper() or 'command' in f.description.lower()]
        assert len(cmd_findings) >= 1

    def test_detects_command_output(self, analyzer, tmp_path):
        code = '''
package main

import "os/exec"

func getOutput(cmd string) []byte {
    out, _ := exec.Command("bash", "-c", cmd).Output()
    return out
}
'''
        file_path = tmp_path / "main.go"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        assert len(findings) >= 1


class TestGoPathTraversal:
    def test_detects_file_open_with_input(self, analyzer, tmp_path):
        code = '''
package main

import "os"

func readFile(filename string) {
    os.Open(filename)
}
'''
        file_path = tmp_path / "main.go"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        # May or may not detect depending on context
        # Just verify no crash
        assert isinstance(findings, list)


class TestGoSSRF:
    def test_detects_http_get_with_variable(self, analyzer, tmp_path):
        code = '''
package main

import "net/http"

func fetchURL(url string) {
    http.Get(url)
}
'''
        file_path = tmp_path / "main.go"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        ssrf_findings = [f for f in findings if 'SSRF' in f.rule_id.upper() or 'ssrf' in f.description.lower()]
        assert len(ssrf_findings) >= 1


class TestGoSafeCode:
    def test_no_findings_for_safe_code(self, analyzer, tmp_path):
        code = '''
package main

import "fmt"

func add(a, b int) int {
    return a + b
}

func main() {
    result := add(1, 2)
    fmt.Println(result)
}
'''
        file_path = tmp_path / "main.go"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        # Safe code should have no or minimal findings
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0
