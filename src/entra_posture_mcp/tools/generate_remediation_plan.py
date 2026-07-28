from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Template

from entra_posture_mcp.models import SecurityIssue


async def execute_generate_remediation_plan(issues: list[dict]) -> str:
    """Generates a Markdown Zero-Trust security report and dry-run CLI scripts from findings."""
    parsed_issues = [SecurityIssue.model_validate(i) for i in issues]

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for issue in parsed_issues:
        summary[issue.severity] += 1

    template_path = (
        Path(__file__).parent.parent / "reports" / "templates" / "security_report.md.j2"
    )

    with open(template_path, encoding="utf-8") as f:
        template = Template(f.read())

    rendered_report = template.render(
        generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        issues=parsed_issues,
        summary=summary,
    )

    return rendered_report
