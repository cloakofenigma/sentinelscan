"""Tests for Swift language analyzer."""

import pytest
from pathlib import Path
from scanengine.analyzers.languages.swift import SwiftAnalyzer
from scanengine.models import Severity


@pytest.fixture
def analyzer():
    return SwiftAnalyzer()


class TestSwiftAnalyzerProperties:
    def test_name(self, analyzer):
        assert analyzer.name == "swift_analyzer"

    def test_supported_extensions(self, analyzer):
        assert '.swift' in analyzer.supported_extensions


class TestSwiftSQLInjection:
    def test_detects_sqlite_exec(self, analyzer, tmp_path):
        code = '''
func getUser(id: String) {
    let query = "SELECT * FROM users WHERE id = '\\(id)'"
    sqlite3_exec(db, query, nil, nil, nil)
}
'''
        file_path = tmp_path / "Database.swift"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        sql_findings = [f for f in findings if 'SQL' in f.rule_id.upper()]
        assert len(sql_findings) >= 1


class TestSwiftCommandInjection:
    def test_detects_process(self, analyzer, tmp_path):
        code = '''
func runCommand(_ cmd: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sh")
    process.arguments = ["-c", cmd]
    try? process.run()
}
'''
        file_path = tmp_path / "Runner.swift"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        cmd_findings = [f for f in findings if 'CMD' in f.rule_id.upper() or 'command' in f.description.lower() or 'Process' in f.description]
        assert len(cmd_findings) >= 1


class TestSwiftDeserialization:
    def test_detects_nskeyedunarchiver(self, analyzer, tmp_path):
        code = '''
func deserialize(data: Data) -> Any? {
    return NSKeyedUnarchiver.unarchiveObject(with: data)
}
'''
        file_path = tmp_path / "Archive.swift"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        deser_findings = [f for f in findings if 'DESER' in f.rule_id.upper() or 'Unarchiver' in f.description]
        assert len(deser_findings) >= 1


class TestSwiftSSRF:
    def test_detects_url_session(self, analyzer, tmp_path):
        code = '''
func fetchData(from urlString: String) {
    guard let url = URL(string: urlString) else { return }
    URLSession.shared.dataTask(with: url).resume()
}
'''
        file_path = tmp_path / "Network.swift"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        ssrf_findings = [f for f in findings if 'SSRF' in f.rule_id.upper() or 'URL' in f.description]
        assert len(ssrf_findings) >= 1
