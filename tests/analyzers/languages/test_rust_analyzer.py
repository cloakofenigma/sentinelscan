"""Tests for Rust language analyzer."""

import pytest
from pathlib import Path
from scanengine.analyzers.languages.rust import RustAnalyzer
from scanengine.models import Severity


@pytest.fixture
def analyzer():
    return RustAnalyzer()


class TestRustAnalyzerProperties:
    def test_name(self, analyzer):
        assert analyzer.name == "rust_analyzer"

    def test_supported_extensions(self, analyzer):
        assert '.rs' in analyzer.supported_extensions


class TestRustUnsafeBlocks:
    def test_detects_unsafe_block(self, analyzer, tmp_path):
        code = '''
fn dangerous() {
    unsafe {
        let ptr: *mut i32 = std::ptr::null_mut();
        *ptr = 42;
    }
}
'''
        file_path = tmp_path / "lib.rs"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        unsafe_findings = [f for f in findings if 'UNSAFE' in f.rule_id.upper() or 'unsafe' in f.description.lower()]
        assert len(unsafe_findings) >= 1

    def test_detects_unsafe_fn(self, analyzer, tmp_path):
        code = '''
unsafe fn dangerous_function() {
    // Unsafe code here
}
'''
        file_path = tmp_path / "lib.rs"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        assert len(findings) >= 1


class TestRustCommandInjection:
    def test_detects_command_new(self, analyzer, tmp_path):
        code = '''
use std::process::Command;

fn run(input: &str) {
    Command::new("sh")
        .arg("-c")
        .arg(input)
        .spawn();
}
'''
        file_path = tmp_path / "lib.rs"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        cmd_findings = [f for f in findings if 'CMD' in f.rule_id.upper() or 'command' in f.description.lower()]
        assert len(cmd_findings) >= 1


class TestRustSafeCode:
    def test_no_critical_findings_for_safe_code(self, analyzer, tmp_path):
        code = '''
fn add(a: i32, b: i32) -> i32 {
    a + b
}

fn main() {
    let result = add(1, 2);
    println!("{}", result);
}
'''
        file_path = tmp_path / "main.rs"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0
