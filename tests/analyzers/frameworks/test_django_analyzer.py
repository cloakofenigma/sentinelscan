"""Tests for Django framework analyzer."""

import pytest
from pathlib import Path
from scanengine.analyzers.frameworks.django import DjangoAnalyzer
from scanengine.models import Severity


@pytest.fixture
def analyzer():
    return DjangoAnalyzer()


class TestDjangoAnalyzerProperties:
    def test_name(self, analyzer):
        assert analyzer.name == "django_analyzer"

    def test_framework_name(self, analyzer):
        assert analyzer.framework_name == "Django"

    def test_supported_extensions(self, analyzer):
        assert '.py' in analyzer.supported_extensions


class TestDjangoFrameworkDetection:
    def test_detects_django_project(self, analyzer):
        files = [Path('settings.py'), Path('views.py')]
        content_cache = {'views.py': 'from django.shortcuts import render'}
        assert analyzer.is_framework_project(files, content_cache)


class TestDjangoSQLInjection:
    def test_detects_raw_query(self, analyzer, tmp_path):
        code = '''
from django.db import connection

def get_user(user_id):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
'''
        file_path = tmp_path / "views.py"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        sql_findings = [f for f in findings if 'SQL' in f.rule_id.upper()]
        assert len(sql_findings) >= 1

    def test_detects_extra_query(self, analyzer, tmp_path):
        code = '''
def search(query):
    return User.objects.extra(where=["name LIKE '%" + query + "%'"])
'''
        file_path = tmp_path / "views.py"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        assert len(findings) >= 1


class TestDjangoDebugMode:
    def test_detects_debug_true(self, analyzer, tmp_path):
        code = '''
DEBUG = True
SECRET_KEY = 'my-secret-key'
'''
        file_path = tmp_path / "settings.py"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        debug_findings = [f for f in findings if 'DEBUG' in f.rule_id.upper() or 'debug' in f.description.lower()]
        assert len(debug_findings) >= 1


class TestDjangoSecretKey:
    def test_detects_hardcoded_secret(self, analyzer, tmp_path):
        code = '''
SECRET_KEY = 'django-insecure-abc123xyz789'
'''
        file_path = tmp_path / "settings.py"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        secret_findings = [f for f in findings if 'SECRET' in f.rule_id.upper()]
        assert len(secret_findings) >= 1


class TestDjangoCSRF:
    def test_detects_csrf_exempt(self, analyzer, tmp_path):
        code = '''
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def api_endpoint(request):
    return JsonResponse({'status': 'ok'})
'''
        file_path = tmp_path / "views.py"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        csrf_findings = [f for f in findings if 'CSRF' in f.rule_id.upper()]
        assert len(csrf_findings) >= 1


class TestDjangoXSS:
    def test_detects_safe_filter(self, analyzer, tmp_path):
        code = '''
from django.utils.safestring import mark_safe

def render_html(user_input):
    return mark_safe(user_input)
'''
        file_path = tmp_path / "utils.py"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        xss_findings = [f for f in findings if 'XSS' in f.rule_id.upper() or 'safe' in f.description.lower()]
        assert len(xss_findings) >= 1
