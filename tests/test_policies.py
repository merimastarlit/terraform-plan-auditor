"""
Tests for policy rules.
These test the policy logic directly — no Claude API calls, no cost.
Run with: python -m pytest tests/ -v
"""

import pytest
from mcp_server.policies.security import (
    check_s3_public_access,
    check_security_group,
    check_ec2_instance_security,
)
from mcp_server.policies.cost import check_ec2_instance_cost
from mcp_server.policies.compliance import check_required_tags, check_naming_convention


# ── SECURITY TESTS ───────────────────────────────────────────────────────────

class TestS3PublicAccess:
    def test_flags_public_access_disabled(self):
        resource = {
            "address": "aws_s3_bucket_public_access_block.test",
            "values": {
                "block_public_acls": False,
                "block_public_policy": False,
                "ignore_public_acls": False,
                "restrict_public_buckets": False,
            }
        }
        findings = check_s3_public_access(resource)
        assert len(findings) == 4
        assert all(f["severity"] == "critical" for f in findings)

    def test_passes_when_all_enabled(self):
        resource = {
            "address": "aws_s3_bucket_public_access_block.test",
            "values": {
                "block_public_acls": True,
                "block_public_policy": True,
                "ignore_public_acls": True,
                "restrict_public_buckets": True,
            }
        }
        findings = check_s3_public_access(resource)
        assert len(findings) == 0


class TestSecurityGroup:
    def test_flags_wide_open_ports(self):
        resource = {
            "address": "aws_security_group.test",
            "values": {
                "ingress": [{
                    "from_port": 0,
                    "to_port": 65535,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"]
                }]
            }
        }
        findings = check_security_group(resource)
        # Should flag wide open ports AND SSH (port 22 is in 0-65535 range)
        assert len(findings) >= 2
        assert all(f["severity"] == "critical" for f in findings)

    def test_flags_ssh_open_to_world(self):
        resource = {
            "address": "aws_security_group.test",
            "values": {
                "ingress": [{
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"]
                }]
            }
        }
        findings = check_security_group(resource)
        assert len(findings) == 1
        assert findings[0]["rule"] == "sg_ssh_open_to_world"

    def test_passes_restricted_cidr(self):
        resource = {
            "address": "aws_security_group.test",
            "values": {
                "ingress": [{
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["10.0.0.0/8"]
                }]
            }
        }
        findings = check_security_group(resource)
        assert len(findings) == 0


class TestEC2Security:
    def test_flags_imdsv1(self):
        resource = {
            "address": "aws_instance.test",
            "values": {
                "metadata_options": {"http_tokens": "optional"},
                "monitoring": True
            }
        }
        findings = check_ec2_instance_security(resource)
        assert len(findings) == 1
        assert findings[0]["rule"] == "ec2_imdsv2_not_required"

    def test_passes_imdsv2_enforced(self):
        resource = {
            "address": "aws_instance.test",
            "values": {
                "metadata_options": {"http_tokens": "required"},
                "monitoring": True
            }
        }
        findings = check_ec2_instance_security(resource)
        assert len(findings) == 0


# ── COST TESTS ───────────────────────────────────────────────────────────────

class TestEC2Cost:
    def test_flags_expensive_instance(self):
        resource = {
            "address": "aws_instance.test",
            "values": {"instance_type": "x2idn.16xlarge"}
        }
        findings = check_ec2_instance_cost(resource)
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_passes_reasonable_instance(self):
        resource = {
            "address": "aws_instance.test",
            "values": {"instance_type": "t3.medium"}
        }
        findings = check_ec2_instance_cost(resource)
        assert len(findings) == 0


# ── COMPLIANCE TESTS ─────────────────────────────────────────────────────────

class TestRequiredTags:
    def test_flags_missing_tags(self):
        resource = {
            "address": "aws_instance.test",
            "type": "aws_instance",
            "values": {"tags": {"Name": "test"}}
        }
        findings = check_required_tags(resource)
        assert len(findings) == 1
        assert "Environment" in findings[0]["issue"]
        assert "Owner" in findings[0]["issue"]
        assert "Project" in findings[0]["issue"]

    def test_passes_all_tags_present(self):
        resource = {
            "address": "aws_instance.test",
            "type": "aws_instance",
            "values": {
                "tags": {
                    "Environment": "prod",
                    "Owner": "platform-team",
                    "Project": "auth-service"
                }
            }
        }
        findings = check_required_tags(resource)
        assert len(findings) == 0


class TestNamingConvention:
    def test_flags_underscores(self):
        resource = {
            "address": "aws_s3_bucket.test",
            "values": {"bucket": "my_bad_bucket"}
        }
        findings = check_naming_convention(resource)
        assert any(f["rule"] == "naming_underscores" for f in findings)

    def test_passes_correct_naming(self):
        resource = {
            "address": "aws_s3_bucket.test",
            "values": {"bucket": "my-good-bucket"}
        }
        findings = check_naming_convention(resource)
        assert len(findings) == 0
