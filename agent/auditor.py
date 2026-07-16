"""
Terraform Plan Auditor Agent

Usage:
    python -m agent.auditor sample_plans/insecure_s3_and_sg.json
"""
# Above is Documents how to run this file from the command line. -m agent.auditor means "run the auditor module inside the agent package."


import asyncio
import sys
from pathlib import Path
import shutil

from dotenv import load_dotenv

load_dotenv()

from claude_agent_sdk import (
    query, ClaudeAgentOptions, AssistantMessage,
    TextBlock, ToolUseBlock, ResultMessage,
)
from langfuse import get_client

langfuse = get_client()

CLAUDE_CLI = shutil.which("claude")
if not CLAUDE_CLI:
    sys.exit("Error: 'claude' not found on PATH. Install: brew install --cask claude-code")


async def run_audit(plan_path: str, output_path: str = None):
    """Run the Terraform plan auditor against a plan file."""

    # Resolve absolute path for the plan file
    abs_plan_path = str(Path(plan_path).resolve())

    # Verify the file exists before starting the agent
    if not Path(abs_plan_path).exists():
        print(f"Error: Plan file not found: {abs_plan_path}")
        sys.exit(1)

    # Import system prompt
    from agent.prompts import AUDITOR_SYSTEM_PROMPT


    options = ClaudeAgentOptions(
        system_prompt=AUDITOR_SYSTEM_PROMPT,
        model="claude-sonnet-4-6",
        max_turns=10,
        cli_path=CLAUDE_CLI,
        allowed_tools=["Read", "mcp__terraform-plan-auditor__read_plan",
                        "mcp__terraform-plan-auditor__check_security",
                        "mcp__terraform-plan-auditor__check_cost",
                        "mcp__terraform-plan-auditor__check_compliance"],
        # Auto-approves tool calls without prompting
        permission_mode="acceptEdits",
        mcp_servers={
            "terraform-plan-auditor": {
                "command": sys.executable,
                "args": ["-m", "mcp_server.server"],
                "cwd": str(Path(__file__).resolve().parent.parent)
            }
        }
    )

    # This starts your custom MCP server as a subprocess. When the agent starts, it launches python -m mcp_server.server automatically. The agent then discovers the 4 tools (read_plan, check_security, check_cost, check_compliance) from that server. sys.executable — uses the same Python that's running the agent (your venv's Python 3.12) cwd — sets the working directory to project root so imports resolve correctly. Path(__file__).resolve().parent.parent means: this file → agent/ → project root


    # The initial instruction to the agent. Simple and direct — the system prompt already defines the workflow.
    prompt = f"Audit the Terraform plan at: {abs_plan_path}"

    print(f"Starting audit of: {abs_plan_path}")
    print("-" * 60)

    report_lines = []

    with langfuse.start_as_current_observation(
        as_type="span",
        name="terraform-audit",
        input={"plan_file": Path(abs_plan_path).name},
    ) as root:
        tool_calls = []

    # This is the agentic loop running. query() handles everything internally — sending requests to Claude, checking stop_reason, executing tool calls, appending results. It yields messages as they stream back. You don't write the while loop yourself — the SDK does it.

        async for message in query(prompt=prompt, options=options):
        
        # As the agent works, it produces messages. Some are text (Claude explaining what it's doing), some are tool calls (not printed here). This block prints only the text portions so you see the agent's reasoning and final report.
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        print(block.text)
                        report_lines.append(block.text)
                    elif isinstance(block, ToolUseBlock):
                        tool_calls.append(block.name)
                        with root.start_as_current_observation(
                            as_type="span",
                            name=block.name,
                            input=block.input,
                        ):
                            pass
            # ResultMessage is the final message — the agent is done. It contains total cost and which model was used. This is the equivalent of stop_reason == "end_turn" — the SDK wraps it in a ResultMessage for you.
            if isinstance(message, ResultMessage):
                model = (
                    list(message.model_usage.keys())[0]
                    if message.model_usage else "unknown"
                )
                root.update(output="\n".join(report_lines))
                root.update_trace(
                    metadata={
                        "cost_usd": message.total_cost_usd,
                        "num_turns": message.num_turns,
                        "model": model,
                        "tools_called": tool_calls,
                    },
                    tags=["terraform-audit"],
                )

                print("-" * 60)
                print(f"Audit complete. Cost: ${message.total_cost_usd:.4f}")
                print(f"Model: {list(message.model_usage.keys())[0] if message.model_usage else 'unknown'}")

    if output_path and report_lines:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text("\n".join(report_lines))
        print(f"Report saved to: {output_path}")




def main():
    if len(sys.argv) < 2:
        print("Usage: python -m agent.auditor <path-to-plan.json> [--output report.md]")
        print("Example: python -m agent.auditor sample_plans/insecure_s3_and_sg.json --output reports/audit.md")
        sys.exit(1)

    plan_path = sys.argv[1]

    output_path = None
    if "--output" in sys.argv:
        output_index = sys.argv.index("--output")
        if output_index + 1 < len(sys.argv):
            output_path = sys.argv[output_index + 1]

    asyncio.run(run_audit(plan_path, output_path))


if __name__ == "__main__":
    main()
