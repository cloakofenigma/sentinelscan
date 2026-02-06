"""Tests for PHP language analyzer."""

import pytest
from pathlib import Path
from scanengine.analyzers.languages.php import PHPAnalyzer
from scanengine.models import Severity


@pytest.fixture
def analyzer():
    return PHPAnalyzer()


class TestPHPAnalyzerProperties:
    def test_name(self, analyzer):
        assert analyzer.name == "php_analyzer"

    def test_supported_extensions(self, analyzer):
        assert '.php' in analyzer.supported_extensions


class TestPHPSQLInjection:
    def test_detects_mysqli_query(self, analyzer, tmp_path):
        code = '''<?php
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
?>'''
        file_path = tmp_path / "index.php"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        sql_findings = [f for f in findings if 'SQL' in f.rule_id.upper()]
        assert len(sql_findings) >= 1

    def test_detects_pdo_query(self, analyzer, tmp_path):
        code = '''<?php
$name = $_POST['name'];
$stmt = $pdo->query("SELECT * FROM users WHERE name = '$name'");
?>'''
        file_path = tmp_path / "query.php"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        assert len(findings) >= 1


class TestPHPCommandInjection:
    def test_detects_shell_exec(self, analyzer, tmp_path):
        code = '''<?php
$cmd = $_GET['cmd'];
$output = shell_exec($cmd);
echo $output;
?>'''
        file_path = tmp_path / "exec.php"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        cmd_findings = [f for f in findings if 'CMD' in f.rule_id.upper() or 'command' in f.description.lower()]
        assert len(cmd_findings) >= 1

    def test_detects_system(self, analyzer, tmp_path):
        code = '''<?php
$input = $_POST['input'];
system("echo " . $input);
?>'''
        file_path = tmp_path / "system.php"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        assert len(findings) >= 1


class TestPHPDeserialization:
    def test_detects_unserialize(self, analyzer, tmp_path):
        code = '''<?php
$data = $_COOKIE['data'];
$obj = unserialize($data);
?>'''
        file_path = tmp_path / "deserialize.php"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        deser_findings = [f for f in findings if 'DESER' in f.rule_id.upper() or 'deserial' in f.description.lower()]
        assert len(deser_findings) >= 1


class TestPHPSafeCode:
    def test_no_critical_findings_for_safe_code(self, analyzer, tmp_path):
        code = '''<?php
function add($a, $b) {
    return $a + $b;
}

echo add(1, 2);
?>'''
        file_path = tmp_path / "safe.php"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0
