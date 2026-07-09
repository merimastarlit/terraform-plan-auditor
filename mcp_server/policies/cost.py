"""
Cost policy rules for Terraform plan auditing.
Each function takes a resource dict and returns a list of findings.
"""

# Instance types that are expensive and rarely justified without review
EXPENSIVE_INSTANCE_TYPES = {
    # Metal instances
    "i3.metal", "i3en.metal", "m5.metal", "m5d.metal", "r5.metal", "z1d.metal",
    # Extra large memory-optimized
    "x2idn.16xlarge", "x2idn.24xlarge", "x2idn.32xlarge",
    "x2iedn.16xlarge", "x2iedn.24xlarge", "x2iedn.32xlarge",
    "x1.16xlarge", "x1.32xlarge", "x1e.16xlarge", "x1e.32xlarge",
    # GPU instances
    "p4d.24xlarge", "p4de.24xlarge", "p5.48xlarge",
    # Large general purpose
    "m5.24xlarge", "m6i.32xlarge", "c5.24xlarge", "r5.24xlarge",
}

# Recommended alternatives for common oversized choices
INSTANCE_ALTERNATIVES = {
    "x2idn.16xlarge": "r6i.4xlarge or r6i.8xlarge — unless you specifically need 512GB+ RAM",
    "m5.24xlarge": "m6i.8xlarge or m6i.12xlarge — newer generation, better price-performance",
    "c5.24xlarge": "c6i.8xlarge or c6i.12xlarge — newer generation, better price-performance",
    "p4d.24xlarge": "g5.12xlarge — unless training large models, inference workloads rarely need p4d",
}


def check_ec2_instance_cost(resource: dict) -> list[dict]:
    """Check EC2 instance for cost concerns."""
    findings = []
    values = resource.get("values", {})
    address = resource.get("address", "unknown")

    instance_type = values.get("instance_type", "")

    if instance_type in EXPENSIVE_INSTANCE_TYPES:
        alternative = INSTANCE_ALTERNATIVES.get(
            instance_type,
            "Review if this instance size is justified for the workload."
        )

        findings.append({
            "resource": address,
            "category": "cost",
            "severity": "high",
            "rule": "ec2_expensive_instance",
            "issue": f"Instance type '{instance_type}' is in the expensive tier. Monthly cost can exceed $5,000.",
            "suggested_fix": f"Consider: {alternative}"
        })

    return findings


def check_ebs_volume_cost(resource: dict) -> list[dict]:
    """Check EBS volumes for cost optimization opportunities."""
    findings = []
    values = resource.get("values", {})
    address = resource.get("address", "unknown")

    volume_type = values.get("type", "")
    size = values.get("size", 0)

    # Large io1/io2 volumes without justification
    if volume_type in ("io1", "io2") and size > 500:
        findings.append({
            "resource": address,
            "category": "cost",
            "severity": "medium",
            "rule": "ebs_large_provisioned_iops",
            "issue": f"Provisioned IOPS volume ({volume_type}) with {size}GB. Provisioned IOPS volumes cost significantly more than gp3.",
            "suggested_fix": "Use gp3 volumes unless sustained IOPS above 16,000 are required. gp3 provides 3,000 baseline IOPS for free."
        })

    return findings


def check_rds_instance_cost(resource: dict) -> list[dict]:
    """Check RDS instances for cost concerns."""
    findings = []
    values = resource.get("values", {})
    address = resource.get("address", "unknown")

    # Multi-AZ on non-production
    multi_az = values.get("multi_az", False)
    tags = values.get("tags", {})
    environment = tags.get("Environment", "").lower()

    if multi_az and environment in ("dev", "development", "staging", "test"):
        findings.append({
            "resource": address,
            "category": "cost",
            "severity": "medium",
            "rule": "rds_multi_az_non_production",
            "issue": f"Multi-AZ is enabled for a {environment} environment. This doubles the RDS cost.",
            "suggested_fix": "Disable Multi-AZ for non-production environments."
        })

    return findings


COST_CHECKS = {
    "aws_instance": check_ec2_instance_cost,
    "aws_ebs_volume": check_ebs_volume_cost,
    "aws_db_instance": check_rds_instance_cost,
}
