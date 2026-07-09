"""
Security policy rules for Terraform plan auditing.
Each function takes a resource dict and returns a list of findings.
"""


def check_s3_bucket(resource: dict) -> list[dict]:
    """Check S3 bucket for security issues."""
    findings = []
    values = resource.get("values", {})
    address = resource.get("address", "unknown")

    # Check for missing tags (no ownership tracking)
    tags = values.get("tags", {})
    if not tags:
        findings.append({
            "resource": address,
            "category": "security",
            "severity": "medium",
            "rule": "s3_no_tags",
            "issue": "S3 bucket has no tags. Cannot track ownership or data classification.",
            "suggested_fix": "Add tags including 'Environment', 'Owner', and 'DataClassification'."
        })

    return findings


def check_s3_public_access(resource: dict) -> list[dict]:
    """Check S3 public access block configuration."""
    findings = []
    values = resource.get("values", {})
    address = resource.get("address", "unknown")

    public_access_fields = [
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets"
    ]

    for field in public_access_fields:
        if values.get(field) is False:
            findings.append({
                "resource": address,
                "category": "security",
                "severity": "critical",
                "rule": f"s3_public_access_{field}",
                "issue": f"S3 public access setting '{field}' is set to false. Bucket data may be publicly accessible.",
                "suggested_fix": f"Set '{field}' to true to prevent public access."
            })

    return findings


def check_security_group(resource: dict) -> list[dict]:
    """Check security group for overly permissive rules."""
    findings = []
    values = resource.get("values", {})
    address = resource.get("address", "unknown")

    ingress_rules = values.get("ingress", [])

    for rule in ingress_rules:
        cidr_blocks = rule.get("cidr_blocks", [])
        from_port = rule.get("from_port", 0)
        to_port = rule.get("to_port", 0)
        protocol = rule.get("protocol", "")

        # Check for 0.0.0.0/0 ingress (open to the world)
        if "0.0.0.0/0" in cidr_blocks:

            # Wide port range open to the world
            if to_port - from_port > 100:
                findings.append({
                    "resource": address,
                    "category": "security",
                    "severity": "critical",
                    "rule": "sg_wide_open_ports",
                    "issue": f"Security group allows inbound traffic on ports {from_port}-{to_port} from 0.0.0.0/0. This exposes a wide port range to the entire internet.",
                    "suggested_fix": "Restrict to specific ports and limit source CIDR blocks to known IP ranges."
                })

            # SSH open to the world
            if from_port <= 22 <= to_port:
                findings.append({
                    "resource": address,
                    "category": "security",
                    "severity": "critical",
                    "rule": "sg_ssh_open_to_world",
                    "issue": "SSH (port 22) is open to 0.0.0.0/0. Anyone on the internet can attempt SSH access.",
                    "suggested_fix": "Restrict SSH access to known IP ranges or use AWS Systems Manager Session Manager instead."
                })

            # RDP open to the world
            if from_port <= 3389 <= to_port:
                findings.append({
                    "resource": address,
                    "category": "security",
                    "severity": "critical",
                    "rule": "sg_rdp_open_to_world",
                    "issue": "RDP (port 3389) is open to 0.0.0.0/0. Anyone on the internet can attempt RDP access.",
                    "suggested_fix": "Restrict RDP access to known IP ranges or use a VPN."
                })

    return findings


def check_ec2_instance_security(resource: dict) -> list[dict]:
    """Check EC2 instance for security issues."""
    findings = []
    values = resource.get("values", {})
    address = resource.get("address", "unknown")

    # Check IMDSv2 enforcement
    metadata_options = values.get("metadata_options", {})
    http_tokens = metadata_options.get("http_tokens", "optional")

    if http_tokens != "required":
        findings.append({
            "resource": address,
            "category": "security",
            "severity": "high",
            "rule": "ec2_imdsv2_not_required",
            "issue": "EC2 instance metadata service is not enforcing IMDSv2. IMDSv1 is vulnerable to SSRF attacks.",
            "suggested_fix": "Set metadata_options.http_tokens to 'required' to enforce IMDSv2."
        })

    # Check monitoring
    if values.get("monitoring") is False:
        findings.append({
            "resource": address,
            "category": "security",
            "severity": "medium",
            "rule": "ec2_monitoring_disabled",
            "issue": "Detailed monitoring is disabled. Security events may not be captured.",
            "suggested_fix": "Set monitoring to true for detailed CloudWatch metrics."
        })

    return findings


# Registry mapping resource types to their check functions
SECURITY_CHECKS = {
    "aws_s3_bucket": check_s3_bucket,
    "aws_s3_bucket_public_access_block": check_s3_public_access,
    "aws_security_group": check_security_group,
    "aws_instance": check_ec2_instance_security,
}
