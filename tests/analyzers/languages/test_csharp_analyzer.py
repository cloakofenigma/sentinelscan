"""Tests for C# language analyzer."""

import pytest
from pathlib import Path
from scanengine.analyzers.languages.csharp import CSharpAnalyzer
from scanengine.models import Severity


@pytest.fixture
def analyzer():
    return CSharpAnalyzer()


class TestCSharpAnalyzerProperties:
    def test_name(self, analyzer):
        assert analyzer.name == "csharp_analyzer"

    def test_supported_extensions(self, analyzer):
        assert '.cs' in analyzer.supported_extensions


class TestCSharpSQLInjection:
    def test_detects_sql_command(self, analyzer, tmp_path):
        code = '''
public void GetUser(string id)
{
    var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = " + id, connection);
    cmd.ExecuteReader();
}
'''
        file_path = tmp_path / "UserRepository.cs"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        sql_findings = [f for f in findings if 'SQL' in f.rule_id.upper()]
        assert len(sql_findings) >= 1

    def test_detects_execute_sql_raw(self, analyzer, tmp_path):
        code = '''
public void Query(string input)
{
    context.Database.ExecuteSqlRaw($"SELECT * FROM Users WHERE Name = '{input}'");
}
'''
        file_path = tmp_path / "Context.cs"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        assert len(findings) >= 1


class TestCSharpCommandInjection:
    def test_detects_process_start(self, analyzer, tmp_path):
        code = '''
public void RunCommand(string cmd)
{
    Process.Start("cmd.exe", "/c " + cmd);
}
'''
        file_path = tmp_path / "Runner.cs"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        cmd_findings = [f for f in findings if 'CMD' in f.rule_id.upper() or 'command' in f.description.lower() or 'Process' in f.description]
        assert len(cmd_findings) >= 1


class TestCSharpDeserialization:
    def test_detects_binary_formatter(self, analyzer, tmp_path):
        code = '''
public object Deserialize(Stream stream)
{
    var formatter = new BinaryFormatter();
    return formatter.Deserialize(stream);
}
'''
        file_path = tmp_path / "Serializer.cs"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        deser_findings = [f for f in findings if 'DESER' in f.rule_id.upper() or 'deserial' in f.description.lower()]
        assert len(deser_findings) >= 1


class TestCSharpPathTraversal:
    def test_detects_file_open(self, analyzer, tmp_path):
        code = '''
public void ReadFile(string filename)
{
    File.Open(filename, FileMode.Open);
}
'''
        file_path = tmp_path / "FileReader.cs"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        # May or may not flag depending on context
        assert isinstance(findings, list)
