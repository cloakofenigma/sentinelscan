"""Tests for Terraform IaC analyzer."""

import pytest
from pathlib import Path
from scanengine.analyzers.iac.terraform import TerraformAnalyzer
from scanengine.models import Severity


@pytest.fixture
def analyzer():
    return TerraformAnalyzer()


class TestTerraformAnalyzerProperties:
    def test_name(self, analyzer):
        assert analyzer.name == "terraform_analyzer"

    def test_iac_type(self, analyzer):
        assert analyzer.iac_type == "terraform"

    def test_supported_extensions(self, analyzer):
        assert '.tf' in analyzer.supported_extensions


class TestTerraformPublicS3:
    def test_detects_public_acl(self, analyzer, tmp_path):
        code = '''
resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
'''
        file_path = tmp_path / "s3.tf"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        s3_findings = [f for f in findings if 'S3' in f.rule_id.upper() or 'public' in f.description.lower()]
        assert len(s3_findings) >= 1

    def test_detects_public_read_write(self, analyzer, tmp_path):
        code = '''
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "public-read-write"
}
'''
        file_path = tmp_path / "storage.tf"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        assert len(findings) >= 1


class TestTerraformSecurityGroup:
    def test_detects_open_ingress(self, analyzer, tmp_path):
        code = '''
resource "aws_security_group" "open" {
  name = "open-sg"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
        file_path = tmp_path / "security.tf"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        sg_findings = [f for f in findings if 'SG' in f.rule_id.upper() or 'security' in f.description.lower() or '0.0.0.0' in f.description]
        assert len(sg_findings) >= 1


class TestTerraformIAM:
    def test_detects_star_permissions(self, analyzer, tmp_path):
        code = '''
resource "aws_iam_policy" "admin" {
  name = "admin-policy"

  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
'''
        file_path = tmp_path / "iam.tf"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        iam_findings = [f for f in findings if 'IAM' in f.rule_id.upper() or 'permission' in f.description.lower()]
        assert len(iam_findings) >= 1


class TestTerraformEncryption:
    def test_detects_unencrypted_ebs(self, analyzer, tmp_path):
        code = '''
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}
'''
        file_path = tmp_path / "ebs.tf"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        enc_findings = [f for f in findings if 'ENCRYPT' in f.rule_id.upper() or 'encrypt' in f.description.lower()]
        assert len(enc_findings) >= 1


class TestTerraformSafeCode:
    def test_no_findings_for_safe_config(self, analyzer, tmp_path):
        code = '''
resource "aws_s3_bucket" "private" {
  bucket = "my-private-bucket"
  acl    = "private"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.private.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
'''
        file_path = tmp_path / "secure.tf"
        file_path.write_text(code)
        findings = analyzer.analyze_file(file_path, code)

        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0
