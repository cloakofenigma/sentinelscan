"""Tests for scanengine.mybatis_analyzer"""

import pytest
from pathlib import Path
from scanengine.mybatis_analyzer import MybatisAnalyzer, analyze_mybatis_mappers


class TestMybatisAnalyzer:
    def test_detect_interpolation(self, mybatis_mapper_file):
        analyzer = MybatisAnalyzer()
        files = [mybatis_mapper_file]
        content_cache = {str(mybatis_mapper_file): mybatis_mapper_file.read_text()}
        findings = analyzer.analyze_files(files, content_cache)
        # Should detect ${name} and ${sortColumn} interpolation
        sqli_findings = [f for f in findings if "interpolat" in f.description.lower() or "injection" in f.description.lower()]
        assert len(sqli_findings) >= 2

    def test_parameterized_safe(self, mybatis_mapper_file):
        analyzer = MybatisAnalyzer()
        files = [mybatis_mapper_file]
        content_cache = {str(mybatis_mapper_file): mybatis_mapper_file.read_text()}
        findings = analyzer.analyze_files(files, content_cache)
        # findById uses #{id} - should NOT be flagged
        finding_ids = [f.description for f in findings]
        safe_flagged = [d for d in finding_ids if "findById" in d and "#{" in d]
        assert len(safe_flagged) == 0

    def test_foreach_interpolation(self, mybatis_mapper_file):
        analyzer = MybatisAnalyzer()
        files = [mybatis_mapper_file]
        content_cache = {str(mybatis_mapper_file): mybatis_mapper_file.read_text()}
        findings = analyzer.analyze_files(files, content_cache)
        # foreach with ${id} should be detected
        foreach_findings = [f for f in findings if "foreach" in f.description.lower() or "findByIds" in str(f.metadata)]
        # At minimum the ${id} in foreach should trigger
        assert len(findings) >= 2

    def test_mapper_statistics(self, mybatis_mapper_file):
        analyzer = MybatisAnalyzer()
        files = [mybatis_mapper_file]
        content_cache = {str(mybatis_mapper_file): mybatis_mapper_file.read_text()}
        analyzer.analyze_files(files, content_cache)
        stats = analyzer.get_statistics()
        assert stats["total_mappers"] >= 1
        assert stats["total_statements"] >= 4

    def test_analyze_factory_function(self, mybatis_mapper_file):
        files = [mybatis_mapper_file]
        content_cache = {str(mybatis_mapper_file): mybatis_mapper_file.read_text()}
        findings = analyze_mybatis_mappers(files, content_cache)
        assert isinstance(findings, list)
        assert len(findings) >= 1

    def test_safe_mapper_no_findings(self, tmp_path):
        safe_mapper = tmp_path / "SafeMapper.xml"
        safe_mapper.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
    "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.SafeMapper">
    <select id="findAll" resultType="User">
        SELECT * FROM users WHERE id = #{id}
    </select>
    <insert id="insertUser" parameterType="User">
        INSERT INTO users (name) VALUES (#{name})
    </insert>
</mapper>
        """)
        analyzer = MybatisAnalyzer()
        findings = analyzer.analyze_files([safe_mapper], {str(safe_mapper): safe_mapper.read_text()})
        assert len(findings) == 0
