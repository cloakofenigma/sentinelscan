"""Tests for multi-language dataflow support."""

import pytest
from scanengine.dataflow.multilang import (
    LanguageDataflowConfig,
    get_language_config,
    get_all_taint_sources,
    get_all_sinks,
    get_all_sanitizers,
    is_taint_source,
    is_sink,
    is_sanitizer,
    get_source_annotation,
    LANGUAGE_CONFIGS,
    GO_CONFIG,
    CSHARP_CONFIG,
    KOTLIN_CONFIG,
    PHP_CONFIG,
    RUBY_CONFIG,
    RUST_CONFIG,
    SWIFT_CONFIG,
)
from scanengine.dataflow_analyzer import TaintSource, SinkType


class TestLanguageConfigs:
    """Test language-specific dataflow configurations."""

    def test_all_configs_exist(self):
        """All 7 language configs should be present (with aliases)."""
        # 7 languages + 4 aliases (cs, kt, rb, rs) = 11 entries
        assert len(LANGUAGE_CONFIGS) == 11

        # Check primary language keys
        assert 'go' in LANGUAGE_CONFIGS
        assert 'csharp' in LANGUAGE_CONFIGS
        assert 'kotlin' in LANGUAGE_CONFIGS
        assert 'php' in LANGUAGE_CONFIGS
        assert 'ruby' in LANGUAGE_CONFIGS
        assert 'rust' in LANGUAGE_CONFIGS
        assert 'swift' in LANGUAGE_CONFIGS

        # Check aliases
        assert 'cs' in LANGUAGE_CONFIGS
        assert 'kt' in LANGUAGE_CONFIGS
        assert 'rb' in LANGUAGE_CONFIGS
        assert 'rs' in LANGUAGE_CONFIGS

    def test_get_language_config(self):
        """get_language_config should return correct configs."""
        go_config = get_language_config('go')
        assert go_config is not None
        assert go_config.language == 'go'
        assert len(go_config.taint_sources) > 0
        assert len(go_config.sink_methods) > 0

        # Unknown language should return None
        unknown = get_language_config('unknown')
        assert unknown is None

    def test_go_config(self):
        """Test Go dataflow configuration."""
        config = GO_CONFIG
        assert config.language == 'go'

        # Check taint sources (method names, not full paths)
        assert 'URL.Query' in config.taint_sources
        assert 'Query' in config.taint_sources
        assert 'Getenv' in config.taint_sources

        # Check sinks (use actual method names from config)
        assert 'Query' in config.sink_methods
        assert config.sink_methods['Query'] == SinkType.SQL_QUERY
        assert 'Command' in config.sink_methods
        assert config.sink_methods['Command'] == SinkType.COMMAND_EXEC

        # Check sanitizers
        assert 'HTMLEscapeString' in config.sanitizers
        assert SinkType.XSS in config.sanitizers['HTMLEscapeString']

    def test_csharp_config(self):
        """Test C# dataflow configuration."""
        config = CSHARP_CONFIG
        assert config.language == 'csharp'

        # Check taint sources
        assert 'Request.QueryString' in config.taint_sources
        assert 'QueryString' in config.taint_sources

        # Check sinks (use actual method names from config)
        assert 'ExecuteReader' in config.sink_methods
        assert config.sink_methods['ExecuteReader'] == SinkType.SQL_QUERY

        # Check source annotations
        assert '[FromQuery]' in config.source_annotations

    def test_kotlin_config(self):
        """Test Kotlin dataflow configuration."""
        config = KOTLIN_CONFIG
        assert config.language == 'kotlin'

        # Check Android-specific sources
        assert 'getStringExtra' in config.taint_sources
        assert 'getString' in config.taint_sources

        # Check sinks (use actual method names from config)
        assert 'rawQuery' in config.sink_methods
        assert 'loadUrl' in config.sink_methods

    def test_php_config(self):
        """Test PHP dataflow configuration."""
        config = PHP_CONFIG
        assert config.language == 'php'

        # Check superglobals
        assert '$_GET' in config.taint_sources
        assert '$_POST' in config.taint_sources
        assert '$_REQUEST' in config.taint_sources

        # Check dangerous functions
        assert 'mysql_query' in config.sink_methods
        assert 'shell_exec' in config.sink_methods
        assert 'unserialize' in config.sink_methods

    def test_ruby_config(self):
        """Test Ruby dataflow configuration."""
        config = RUBY_CONFIG
        assert config.language == 'ruby'

        # Check Rails-specific sources
        assert 'params' in config.taint_sources
        assert 'request.body' in config.taint_sources

        # Check dangerous methods
        assert 'find_by_sql' in config.sink_methods
        assert 'system' in config.sink_methods
        assert 'YAML.load' in config.sink_methods

    def test_rust_config(self):
        """Test Rust dataflow configuration."""
        config = RUST_CONFIG
        assert config.language == 'rust'

        # Check sources
        assert 'env::args' in config.taint_sources
        assert 'stdin' in config.taint_sources

        # Check sinks
        assert 'Command::new' in config.sink_methods
        assert config.sink_methods['Command::new'] == SinkType.COMMAND_EXEC

    def test_swift_config(self):
        """Test Swift dataflow configuration."""
        config = SWIFT_CONFIG
        assert config.language == 'swift'

        # Check iOS-specific sources
        assert 'UserDefaults.string' in config.taint_sources
        assert 'UIPasteboard.string' in config.taint_sources

        # Check iOS-specific sinks
        assert 'sqlite3_exec' in config.sink_methods
        assert 'WKWebView.loadHTMLString' in config.sink_methods


class TestHelperFunctions:
    """Test helper functions for dataflow analysis."""

    def test_get_all_taint_sources(self):
        """Test getting taint sources for a language."""
        php_sources = get_all_taint_sources('php')
        assert len(php_sources) > 0

        # Check PHP sources are included
        assert '$_GET' in php_sources
        assert '$_POST' in php_sources

    def test_get_all_sinks(self):
        """Test getting sinks for a language."""
        go_sinks = get_all_sinks('go')
        assert len(go_sinks) > 0

        # Check Go sinks (use actual method names)
        assert 'Query' in go_sinks
        assert 'Command' in go_sinks

    def test_get_all_sanitizers(self):
        """Test getting sanitizers for a language."""
        csharp_sanitizers = get_all_sanitizers('csharp')
        assert len(csharp_sanitizers) > 0

    def test_is_taint_source(self):
        """Test checking if a method is a taint source."""
        # Note: argument order is (language, method_name)
        result = is_taint_source('php', '$_GET')
        assert result == TaintSource.HTTP_PARAMETER

        result = is_taint_source('ruby', 'params')
        assert result == TaintSource.HTTP_PARAMETER

        result = is_taint_source('go', 'Getenv')
        assert result == TaintSource.ENVIRONMENT

        # Non-existent source should return None
        result = is_taint_source('go', 'not_a_source')
        assert result is None

    def test_is_sink(self):
        """Test checking if a method is a sink."""
        sink_type = is_sink('php', 'mysql_query')
        assert sink_type == SinkType.SQL_QUERY

        sink_type = is_sink('php', 'shell_exec')
        assert sink_type == SinkType.COMMAND_EXEC

        sink_type = is_sink('php', 'not_a_sink')
        assert sink_type is None

    def test_is_sanitizer(self):
        """Test checking if a method is a sanitizer."""
        # Note: is_sanitizer takes (language, method_name, sink_type) and returns bool
        result = is_sanitizer('php', 'htmlspecialchars', SinkType.XSS)
        assert result is True

        result = is_sanitizer('php', 'htmlspecialchars', SinkType.SQL_QUERY)
        assert result is False

        result = is_sanitizer('php', 'not_a_sanitizer', SinkType.XSS)
        assert result is False

    def test_get_source_annotation(self):
        """Test getting source type from annotations."""
        source_type = get_source_annotation('csharp', '[FromQuery]')
        assert source_type == TaintSource.HTTP_PARAMETER

        source_type = get_source_annotation('kotlin', '@RequestParam')
        assert source_type == TaintSource.HTTP_PARAMETER

        source_type = get_source_annotation('csharp', '[NotAnAnnotation]')
        assert source_type is None


class TestAnalyzerIntegration:
    """Test that analyzers properly integrate with dataflow configs."""

    def test_go_analyzer_integration(self):
        """Test Go analyzer dataflow integration."""
        from scanengine.analyzers.languages.go import GoAnalyzer
        analyzer = GoAnalyzer()

        assert analyzer.capabilities.supports_dataflow is True
        config = analyzer.dataflow_config
        assert config is not None
        assert config.language == 'go'

    def test_csharp_analyzer_integration(self):
        """Test C# analyzer dataflow integration."""
        from scanengine.analyzers.languages.csharp import CSharpAnalyzer
        analyzer = CSharpAnalyzer()

        assert analyzer.capabilities.supports_dataflow is True
        config = analyzer.dataflow_config
        assert config is not None
        assert config.language == 'csharp'

    def test_kotlin_analyzer_integration(self):
        """Test Kotlin analyzer dataflow integration."""
        from scanengine.analyzers.languages.kotlin import KotlinAnalyzer
        analyzer = KotlinAnalyzer()

        assert analyzer.capabilities.supports_dataflow is True
        config = analyzer.dataflow_config
        assert config is not None
        assert config.language == 'kotlin'

    def test_php_analyzer_integration(self):
        """Test PHP analyzer dataflow integration."""
        from scanengine.analyzers.languages.php import PHPAnalyzer
        analyzer = PHPAnalyzer()

        assert analyzer.capabilities.supports_dataflow is True
        config = analyzer.dataflow_config
        assert config is not None
        assert config.language == 'php'

    def test_ruby_analyzer_integration(self):
        """Test Ruby analyzer dataflow integration."""
        from scanengine.analyzers.languages.ruby import RubyAnalyzer
        analyzer = RubyAnalyzer()

        assert analyzer.capabilities.supports_dataflow is True
        config = analyzer.dataflow_config
        assert config is not None
        assert config.language == 'ruby'

    def test_rust_analyzer_integration(self):
        """Test Rust analyzer dataflow integration."""
        from scanengine.analyzers.languages.rust import RustAnalyzer
        analyzer = RustAnalyzer()

        assert analyzer.capabilities.supports_dataflow is True
        config = analyzer.dataflow_config
        assert config is not None
        assert config.language == 'rust'

    def test_swift_analyzer_integration(self):
        """Test Swift analyzer dataflow integration."""
        from scanengine.analyzers.languages.swift import SwiftAnalyzer
        analyzer = SwiftAnalyzer()

        assert analyzer.capabilities.supports_dataflow is True
        config = analyzer.dataflow_config
        assert config is not None
        assert config.language == 'swift'
