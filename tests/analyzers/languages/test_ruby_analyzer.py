"""Tests for Ruby language analyzer."""

import pytest
from pathlib import Path
from scanengine.analyzers.languages.ruby import RubyAnalyzer
from scanengine.models import Severity


@pytest.fixture
def analyzer():
    return RubyAnalyzer()


class TestRubyAnalyzerProperties:
    def test_name(self, analyzer):
        assert analyzer.name == "ruby_analyzer"

    def test_supported_extensions(self, analyzer):
        assert '.rb' in analyzer.supported_extensions
        assert '.rake' in analyzer.supported_extensions


class TestRubySQLInjection:
    def test_detects_find_by_sql(self, analyzer, tmp_path):
        code = '''
class UserController < ApplicationController
  def show
    @user = User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")
  end
end
'''
        file_path = tmp_path / "user_controller.rb"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        sql_findings = [f for f in findings if 'SQL' in f.rule_id.upper()]
        assert len(sql_findings) >= 1


class TestRubyCommandInjection:
    def test_detects_system_call(self, analyzer, tmp_path):
        code = '''
def run_command(input)
  system("echo #{input}")
end
'''
        file_path = tmp_path / "runner.rb"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        cmd_findings = [f for f in findings if 'CMD' in f.rule_id.upper() or 'command' in f.description.lower()]
        assert len(cmd_findings) >= 1

    def test_detects_backticks(self, analyzer, tmp_path):
        code = '''
def execute(cmd)
  result = `#{cmd}`
  result
end
'''
        file_path = tmp_path / "exec.rb"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        assert len(findings) >= 1


class TestRubyDeserialization:
    def test_detects_yaml_load(self, analyzer, tmp_path):
        code = '''
require 'yaml'

def parse_config(data)
  YAML.load(data)
end
'''
        file_path = tmp_path / "config.rb"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        deser_findings = [f for f in findings if 'DESER' in f.rule_id.upper() or 'YAML' in f.rule_id.upper()]
        assert len(deser_findings) >= 1

    def test_detects_marshal_load(self, analyzer, tmp_path):
        code = '''
def deserialize(data)
  Marshal.load(data)
end
'''
        file_path = tmp_path / "marshal.rb"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        assert len(findings) >= 1
