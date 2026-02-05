"""Tests for scanengine.spring_analyzer"""

import pytest
from pathlib import Path
from scanengine.spring_analyzer import SpringAnalyzer, analyze_spring_application


class TestSpringAnalyzer:
    def test_detect_spring_endpoints(self, spring_controller_file):
        analyzer = SpringAnalyzer()
        files = [spring_controller_file]
        content_cache = {str(spring_controller_file): spring_controller_file.read_text()}
        findings = analyzer.analyze_files(files, content_cache)
        # Should detect endpoints and potential issues
        assert isinstance(findings, list)

    def test_detect_csrf_disabled(self, spring_security_config_file):
        analyzer = SpringAnalyzer()
        files = [spring_security_config_file]
        content_cache = {str(spring_security_config_file): spring_security_config_file.read_text()}
        findings = analyzer.analyze_files(files, content_cache)
        # Should detect csrf().disable()
        csrf_findings = [f for f in findings if "csrf" in f.rule_name.lower() or "csrf" in f.description.lower()]
        assert len(csrf_findings) >= 1

    def test_detect_cors_allow_all(self, spring_security_config_file):
        analyzer = SpringAnalyzer()
        files = [spring_security_config_file]
        content_cache = {str(spring_security_config_file): spring_security_config_file.read_text()}
        findings = analyzer.analyze_files(files, content_cache)
        cors_findings = [f for f in findings if "cors" in f.rule_name.lower() or "cors" in f.description.lower()]
        assert len(cors_findings) >= 1

    def test_detect_missing_validation(self, spring_controller_file):
        analyzer = SpringAnalyzer()
        files = [spring_controller_file]
        content_cache = {str(spring_controller_file): spring_controller_file.read_text()}
        findings = analyzer.analyze_files(files, content_cache)
        # Should find missing @Valid on @RequestBody
        validation_findings = [f for f in findings if "valid" in f.rule_name.lower() or "valid" in f.description.lower()]
        assert len(validation_findings) >= 1

    def test_analyze_spring_application_factory(self, spring_controller_file, spring_security_config_file):
        files = [spring_controller_file, spring_security_config_file]
        content_cache = {str(f): f.read_text() for f in files}
        findings = analyze_spring_application(files, content_cache)
        assert isinstance(findings, list)
        assert len(findings) >= 1

    def test_safe_config_no_extra_findings(self, tmp_path):
        safe = tmp_path / "SafeConfig.java"
        safe.write_text("""
        @Configuration
        public class SafeConfig extends WebSecurityConfigurerAdapter {
            @Override
            protected void configure(HttpSecurity http) throws Exception {
                http
                    .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                    .and()
                    .authorizeRequests()
                    .anyRequest().authenticated();
            }
        }
        """)
        analyzer = SpringAnalyzer()
        findings = analyzer.analyze_files([safe], {str(safe): safe.read_text()})
        csrf_disabled = [f for f in findings if "csrf" in f.rule_name.lower() and "disable" in f.description.lower()]
        assert len(csrf_disabled) == 0
