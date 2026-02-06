"""Tests for React framework analyzer."""

import pytest
from pathlib import Path
from scanengine.analyzers.frameworks.react import ReactAnalyzer
from scanengine.models import Severity


@pytest.fixture
def analyzer():
    return ReactAnalyzer()


class TestReactAnalyzerProperties:
    def test_name(self, analyzer):
        assert analyzer.name == "react_analyzer"

    def test_framework_name(self, analyzer):
        assert analyzer.framework_name == "React"

    def test_supported_extensions(self, analyzer):
        assert '.jsx' in analyzer.supported_extensions
        assert '.tsx' in analyzer.supported_extensions


class TestReactFrameworkDetection:
    def test_detects_react_project(self, analyzer):
        files = [Path('package.json'), Path('src/App.jsx')]
        content_cache = {'package.json': '{"dependencies": {"react": "18.0.0"}}'}
        assert analyzer.is_framework_project(files, content_cache)

    def test_rejects_non_react_project(self, analyzer):
        files = [Path('package.json')]
        content_cache = {'package.json': '{"dependencies": {"vue": "3.0.0"}}'}
        assert not analyzer.is_framework_project(files, content_cache)


class TestReactXSS:
    def test_detects_dangerously_set_inner_html(self, analyzer, tmp_path):
        code = '''
import React from 'react';

function App({ userContent }) {
    return <div dangerouslySetInnerHTML={{__html: userContent}} />;
}
'''
        file_path = tmp_path / "App.jsx"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        xss_findings = [f for f in findings if 'XSS' in f.rule_id.upper()]
        assert len(xss_findings) >= 1
        assert findings[0].severity in (Severity.HIGH, Severity.MEDIUM)

    def test_detects_javascript_href(self, analyzer, tmp_path):
        code = '''
import React from 'react';

function Link() {
    return <a href="javascript:alert('xss')">Click</a>;
}
'''
        file_path = tmp_path / "Link.jsx"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        href_findings = [f for f in findings if 'XSS' in f.rule_id.upper() or 'href' in f.description.lower()]
        assert len(href_findings) >= 1


class TestReactEval:
    def test_detects_eval(self, analyzer, tmp_path):
        code = '''
function executeCode(code) {
    eval(code);
}
'''
        file_path = tmp_path / "executor.js"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        eval_findings = [f for f in findings if 'EVAL' in f.rule_id.upper() or 'eval' in f.description.lower()]
        assert len(eval_findings) >= 1


class TestReactLocalStorage:
    def test_detects_sensitive_data_in_storage(self, analyzer, tmp_path):
        code = '''
function saveToken(token) {
    localStorage.setItem('auth_token', token);
}
'''
        file_path = tmp_path / "auth.js"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        storage_findings = [f for f in findings if 'STORAGE' in f.rule_id.upper() or 'localStorage' in f.description]
        assert len(storage_findings) >= 1


class TestReactUnsafeTarget:
    def test_detects_blank_without_noopener(self, analyzer, tmp_path):
        code = '''
function ExternalLink({ url }) {
    return <a href={url} target="_blank">External</a>;
}
'''
        file_path = tmp_path / "Link.jsx"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        link_findings = [f for f in findings if 'LINK' in f.rule_id.upper() or 'target' in f.description.lower()]
        assert len(link_findings) >= 1


class TestReactSafeCode:
    def test_no_findings_for_safe_code(self, analyzer, tmp_path):
        code = '''
import React from 'react';

function SafeComponent({ name }) {
    return <div>Hello, {name}</div>;
}

export default SafeComponent;
'''
        file_path = tmp_path / "Safe.jsx"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0
