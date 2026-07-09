"""
Custom MCP server for Terraform plan auditing.

Exposes tools for:
- Reading and parsing Terraform plan JSON files
- Running security, cost, and compliance policy checks
- Generating structured audit reports
"""

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from mcp_server.policies.security import SECURITY_CHECKS
from mcp_server.policies.cost import COST_CHECKS
from mcp_server.policies.compliance import COMPLIANCE_CHECKS, check_region_compliance
mcp = FastMCP("terraform-plan-auditor")


@mcp.tool()
def read_plan(file_path: str) -> str:
    """Read and parse a Terraform plan JSON file.

    USE THIS TOOL WHEN:
    - Starting an audit — always call this first to load the plan
    - You need to examine what resources are being created, modified, or destroyed

    DO NOT USE THIS TOOL WHEN:
    - You have already loaded the plan in this session
    - You need to run policy checks — use check_security, check_cost, or check_compliance instead

    ACCEPTS: file_path — path to a Terraform plan JSON file (output of 'terraform show -json')
    RETURNS: Structured summary of all resource changes in the plan
    """
    path = Path(file_path)

    if not path.exists():
        return json.dumps({
            "status": "error",
            "error_category": "validation",
            "is_retryable": False,
            "message": f"File not found: {file_path}"
        })

    if not path.suffix == ".json":
        return json.dumps({
            "status": "error",
            "error_category": "validation",
            "is_retryable": False,
            "message": f"Expected a JSON file, got: {path.suffix}"
        })

    try:
        plan_data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        return json.dumps({
            "status": "error",
            "error_category": "validation",
            "is_retryable": False,
            "message": f"Invalid JSON in plan file: {str(e)}"
        })

    # Extract resource changes
    resource_changes = plan_data.get("resource_changes", [])
    planned_values = plan_data.get("planned_values", {})
    provider_config = plan_data.get("configuration", {}).get("provider_config", {})

    # Build summary of resources
    resources = []
    for change in resource_changes:
        resources.append({
            "address": change.get("address"),
            "type": change.get("type"),
            "name": change.get("name"),
            "actions": change.get("change", {}).get("actions", []),
            "values": change.get("change", {}).get("after", {})
        })

    # Also include planned_values resources for full picture
    pv_resources = planned_values.get("root_module", {}).get("resources", [])

    return json.dumps({
        "status": "success",
        "terraform_version": plan_data.get("terraform_version"),
        "resource_count": len(resources),
        "resources": resources,
        "planned_values_resources": pv_resources,
        "provider_config": provider_config
    })


@mcp.tool()
def check_security(plan_json: str) -> str:
    """Run security policy checks against parsed Terraform plan resources.

    USE THIS TOOL WHEN:
    - You have already loaded the plan with read_plan
    - You need to identify security vulnerabilities in the planned infrastructure

    DO NOT USE THIS TOOL WHEN:
    - You have not loaded the plan yet — call read_plan first
    - You need cost or compliance checks — use check_cost or check_compliance instead

    ACCEPTS: plan_json — the JSON string returned by read_plan
    RETURNS: List of security findings with severity, issue description, and suggested fixes
    """
    try:
        plan_data = json.loads(plan_json)
    except json.JSONDecodeError:
        return json.dumps({
            "status": "error",
            "error_category": "validation",
            "is_retryable": False,
            "message": "Invalid JSON input. Pass the exact output from read_plan."
        })

    if plan_data.get("status") == "error":
        return json.dumps({
            "status": "error",
            "error_category": "validation",
            "is_retryable": False,
            "message": "Plan data contains an error. Load a valid plan with read_plan first."
        })

    findings = []
    resources = plan_data.get("planned_values_resources", [])

    for resource in resources:
        resource_type = resource.get("type", "")
        check_fn = SECURITY_CHECKS.get(resource_type)

        if check_fn:
            findings.extend(check_fn(resource))

    return json.dumps({
        "status": "success",
        "check_type": "security",
        "total_findings": len(findings),
        "critical_count": sum(1 for f in findings if f["severity"] == "critical"),
        "high_count": sum(1 for f in findings if f["severity"] == "high"),
        "medium_count": sum(1 for f in findings if f["severity"] == "medium"),
        "low_count": sum(1 for f in findings if f["severity"] == "low"),
        "findings": findings
    })


@mcp.tool()
def check_cost(plan_json: str) -> str:
    """Run cost policy checks against parsed Terraform plan resources.

    USE THIS TOOL WHEN:
    - You have already loaded the plan with read_plan
    - You need to identify cost optimization opportunities

    DO NOT USE THIS TOOL WHEN:
    - You have not loaded the plan yet — call read_plan first
    - You need security or compliance checks — use check_security or check_compliance instead

    ACCEPTS: plan_json — the JSON string returned by read_plan
    RETURNS: List of cost findings with severity, issue description, and suggested alternatives
    """
    try:
        plan_data = json.loads(plan_json)
    except json.JSONDecodeError:
        return json.dumps({
            "status": "error",
            "error_category": "validation",
            "is_retryable": False,
            "message": "Invalid JSON input. Pass the exact output from read_plan."
        })

    if plan_data.get("status") == "error":
        return json.dumps({
            "status": "error",
            "error_category": "validation",
            "is_retryable": False,
            "message": "Plan data contains an error. Load a valid plan with read_plan first."
        })

    findings = []
    resources = plan_data.get("planned_values_resources", [])

    for resource in resources:
        resource_type = resource.get("type", "")
        check_fn = COST_CHECKS.get(resource_type)

        if check_fn:
            findings.extend(check_fn(resource))

    return json.dumps({
        "status": "success",
        "check_type": "cost",
        "total_findings": len(findings),
        "findings": findings
    })


@mcp.tool()
def check_compliance(plan_json: str) -> str:
    """Run compliance policy checks against parsed Terraform plan resources.

    USE THIS TOOL WHEN:
    - You have already loaded the plan with read_plan
    - You need to verify tagging, naming conventions, and region compliance

    DO NOT USE THIS TOOL WHEN:
    - You have not loaded the plan yet — call read_plan first
    - You need security or cost checks — use check_security or check_cost instead

    ACCEPTS: plan_json — the JSON string returned by read_plan
    RETURNS: List of compliance findings with severity, issue description, and required actions
    """
    try:
        plan_data = json.loads(plan_json)
    except json.JSONDecodeError:
        return json.dumps({
            "status": "error",
            "error_category": "validation",
            "is_retryable": False,
            "message": "Invalid JSON input. Pass the exact output from read_plan."
        })

    if plan_data.get("status") == "error":
        return json.dumps({
            "status": "error",
            "error_category": "validation",
            "is_retryable": False,
            "message": "Plan data contains an error. Load a valid plan with read_plan first."
        })

    findings = []
    resources = plan_data.get("planned_values_resources", [])

    # Check each resource for compliance
    for resource in resources:
        resource_type = resource.get("type", "")
        check_fns = COMPLIANCE_CHECKS.get(resource_type, [])

        for check_fn in check_fns:
            findings.extend(check_fn(resource))

    # Check region compliance from provider config
    provider_config = plan_data.get("provider_config", {})
    if provider_config:
        findings.extend(check_region_compliance(provider_config))

    return json.dumps({
        "status": "success",
        "check_type": "compliance",
        "total_findings": len(findings),
        "findings": findings
    })


if __name__ == "__main__":
    mcp.run()
