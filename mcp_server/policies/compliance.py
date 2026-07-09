"""
Compliance policy rules for Terraform plan auditing.
Each function takes a resource dict and returns a list of findings.
"""

REQUIRED_TAGS = ["Environment", "Owner", "Project"]

ALLOWED_REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]


def check_required_tags(resource: dict) -> list[dict]:
    """Check that all required tags are present on taggable resources."""
    findings = []
    values = resource.get("values", {})
    address = resource.get("address", "unknown")
    resource_type = resource.get("type", "")

    # Only check resources that support tags
    tags = values.get("tags")
    if tags is None:
        return findings

    missing_tags = [tag for tag in REQUIRED_TAGS if tag not in tags]

    if missing_tags:
        findings.append({
            "resource": address,
            "category": "compliance",
            "severity": "medium",
            "rule": "missing_required_tags",
            "issue": f"Resource is missing required tags: {', '.join(missing_tags)}.",
            "suggested_fix": f"Add the following tags: {', '.join(missing_tags)}. All resources must have {', '.join(REQUIRED_TAGS)} tags per organizational policy."
        })

    return findings


def check_naming_convention(resource: dict) -> list[dict]:
    """Check that resource names follow naming conventions."""
    findings = []
    values = resource.get("values", {})
    address = resource.get("address", "unknown")

    # Check common name fields
    name = values.get("name") or values.get("bucket") or ""

    if not name:
        return findings

    # Names should be lowercase with hyphens, no underscores or uppercase
    if name != name.lower():
        findings.append({
            "resource": address,
            "category": "compliance",
            "severity": "low",
            "rule": "naming_uppercase",
            "issue": f"Resource name '{name}' contains uppercase characters.",
            "suggested_fix": "Use lowercase names with hyphens as separators (e.g., 'my-app-bucket')."
        })

    if "_" in name:
        findings.append({
            "resource": address,
            "category": "compliance",
            "severity": "low",
            "rule": "naming_underscores",
            "issue": f"Resource name '{name}' contains underscores.",
            "suggested_fix": "Use hyphens instead of underscores (e.g., 'my-app-bucket' not 'my_app_bucket')."
        })

    return findings


def check_region_compliance(provider_config: dict) -> list[dict]:
    """Check that resources are deployed in allowed regions."""
    findings = []

    aws_config = provider_config.get("aws", {})
    expressions = aws_config.get("expressions", {})
    region_config = expressions.get("region", {})
    region = region_config.get("constant_value", "")

    if region and region not in ALLOWED_REGIONS:
        findings.append({
            "resource": "provider.aws",
            "category": "compliance",
            "severity": "high",
            "rule": "region_not_allowed",
            "issue": f"Region '{region}' is not in the list of approved regions.",
            "suggested_fix": f"Use one of the approved regions: {', '.join(ALLOWED_REGIONS)}."
        })

    return findings


COMPLIANCE_CHECKS = {
    "aws_s3_bucket": [check_required_tags, check_naming_convention],
    "aws_instance": [check_required_tags, check_naming_convention],
    "aws_security_group": [check_required_tags, check_naming_convention],
    "aws_db_instance": [check_required_tags, check_naming_convention],
}
