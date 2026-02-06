"""Tests for Flask framework analyzer."""

import pytest
from pathlib import Path
from scanengine.analyzers.frameworks.flask import FlaskAnalyzer
from scanengine.models import Severity


@pytest.fixture
def analyzer():
    return FlaskAnalyzer()


class TestFlaskAnalyzerProperties:
    def test_name(self, analyzer):
        assert analyzer.name == "flask_analyzer"

    def test_framework_name(self, analyzer):
        assert analyzer.framework_name == "Flask"


class TestFlaskFrameworkDetection:
    def test_detects_flask_project(self, analyzer):
        files = [Path('app.py')]
        content_cache = {'app.py': 'from flask import Flask\napp = Flask(__name__)'}
        assert analyzer.is_framework_project(files, content_cache)


class TestFlaskDebugMode:
    def test_detects_debug_run(self, analyzer, tmp_path):
        code = '''
from flask import Flask
app = Flask(__name__)

if __name__ == '__main__':
    app.run(debug=True)
'''
        file_path = tmp_path / "app.py"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        debug_findings = [f for f in findings if 'DEBUG' in f.rule_id.upper() or 'CONFIG' in f.rule_id.upper()]
        assert len(debug_findings) >= 1

    def test_detects_debug_config(self, analyzer, tmp_path):
        code = '''
app.debug = True
'''
        file_path = tmp_path / "config.py"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        assert len(findings) >= 1


class TestFlaskSecretKey:
    def test_detects_hardcoded_secret(self, analyzer, tmp_path):
        code = '''
app.secret_key = 'super-secret-key-12345'
'''
        file_path = tmp_path / "app.py"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        secret_findings = [f for f in findings if 'SECRET' in f.rule_id.upper()]
        assert len(secret_findings) >= 1


class TestFlaskSQLInjection:
    def test_detects_execute_fstring(self, analyzer, tmp_path):
        code = '''
def get_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        file_path = tmp_path / "db.py"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        sql_findings = [f for f in findings if 'SQL' in f.rule_id.upper()]
        assert len(sql_findings) >= 1


class TestFlaskSSTI:
    def test_detects_render_template_string(self, analyzer, tmp_path):
        code = '''
from flask import render_template_string, request

@app.route('/greet')
def greet():
    name = request.args.get('name')
    return render_template_string(f'<h1>Hello {name}</h1>')
'''
        file_path = tmp_path / "views.py"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        ssti_findings = [f for f in findings if 'SSTI' in f.rule_id.upper() or 'template' in f.description.lower()]
        assert len(ssti_findings) >= 1


class TestFlaskOpenRedirect:
    def test_detects_redirect_from_args(self, analyzer, tmp_path):
        code = '''
from flask import redirect, request

@app.route('/goto')
def goto():
    return redirect(request.args.get('url'))
'''
        file_path = tmp_path / "views.py"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        redirect_findings = [f for f in findings if 'REDIRECT' in f.rule_id.upper()]
        assert len(redirect_findings) >= 1
