"""Tests for Kotlin language analyzer."""

import pytest
from pathlib import Path
from scanengine.analyzers.languages.kotlin import KotlinAnalyzer
from scanengine.models import Severity


@pytest.fixture
def analyzer():
    return KotlinAnalyzer()


class TestKotlinAnalyzerProperties:
    def test_name(self, analyzer):
        assert analyzer.name == "kotlin_analyzer"

    def test_supported_extensions(self, analyzer):
        assert '.kt' in analyzer.supported_extensions
        assert '.kts' in analyzer.supported_extensions


class TestKotlinSQLInjection:
    def test_detects_raw_query(self, analyzer, tmp_path):
        code = '''
fun getUser(db: SQLiteDatabase, id: String): Cursor {
    return db.rawQuery("SELECT * FROM users WHERE id = $id", null)
}
'''
        file_path = tmp_path / "UserDao.kt"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        sql_findings = [f for f in findings if 'SQL' in f.rule_id.upper()]
        assert len(sql_findings) >= 1


class TestKotlinCommandInjection:
    def test_detects_runtime_exec(self, analyzer, tmp_path):
        code = '''
fun executeCommand(cmd: String) {
    Runtime.getRuntime().exec(cmd)
}
'''
        file_path = tmp_path / "Executor.kt"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        cmd_findings = [f for f in findings if 'CMD' in f.rule_id.upper() or 'command' in f.description.lower()]
        assert len(cmd_findings) >= 1

    def test_detects_process_builder(self, analyzer, tmp_path):
        code = '''
fun runProcess(command: String) {
    ProcessBuilder(command.split(" ")).start()
}
'''
        file_path = tmp_path / "Process.kt"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        assert len(findings) >= 1


class TestKotlinWebView:
    def test_detects_javascript_enabled(self, analyzer, tmp_path):
        code = '''
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        val webView = WebView(this)
        webView.settings.javaScriptEnabled = true
        webView.loadUrl(intent.getStringExtra("url"))
    }
}
'''
        file_path = tmp_path / "MainActivity.kt"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        webview_findings = [f for f in findings if 'WEBVIEW' in f.rule_id.upper() or 'WebView' in f.description]
        assert len(webview_findings) >= 1
