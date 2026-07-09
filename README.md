# Terraform Plan Auditor Agent

An AI agent that audits Terraform plan JSON files for security vulnerabilities, cost concerns, and compliance violations — built with the Claude Agent SDK and a custom MCP server.

## Architecture

```
terraform plan -json → plan.json → Agent → MCP Server → Policy Rules → Audit Report
```

- **Agent** (Claude Agent SDK) — reads the plan, orchestrates policy checks, synthesizes findings into a structured report
- **MCP Server** (custom) — exposes plan parsing and policy checking as tools the agent calls
- **Policy Rules** — deterministic Python functions that check resources against security, cost, and compliance policies

## What It Catches

**Security** — public S3 buckets, open security groups (SSH/RDP to 0.0.0.0/0), wide port ranges, IMDSv1, disabled monitoring

**Cost** — oversized EC2 instances (metal, GPU, high-memory), provisioned IOPS volumes, Multi-AZ on non-production

**Compliance** — missing required tags (Environment, Owner, Project), naming convention violations, unapproved regions

## Sample Output

Executive Summary:
Severity - Count
Critical - 8
High - 2
Medium - 5
Total - 15

Overall Verdict: FAIL — Critical findings present. Plan must not be applied as-is.

See `reports/` for full audit report examples.


## Quick Start

```bash
# Clone and setup
git clone git@github.com:merimastarlit/terraform-plan-auditor.git
cd terraform-plan-auditor
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Add your API key
echo "ANTHROPIC_API_KEY=your-key-here" > .env

# Run the auditor
python -m agent.auditor sample_plans/insecure_s3_and_sg.json

# Run tests (no API calls, no cost)
python -m pytest tests/ -v
```

## Project Structure

```
terraform-plan-auditor/
    agent/
        auditor.py          # main agent entry point
        prompts.py          # system prompts
    mcp_server/
        server.py           # custom MCP server with tools
        policies/
            security.py     # security policy rules
            cost.py         # cost policy rules
            compliance.py   # compliance policy rules
    sample_plans/           # sample Terraform plan JSON files
    tests/                  # unit tests for policy rules
```

## CI/CD Integration

Generate a plan JSON in your pipeline and pass it to the agent:

```bash
terraform plan -out=plan.tfplan
terraform show -json plan.tfplan > plan.json
python -m agent.auditor plan.json
```


## Built With

- [Claude Agent SDK](https://docs.anthropic.com) — agentic loop and orchestration
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io) — custom tool server
- Python 3.12, Pydantic, pytest