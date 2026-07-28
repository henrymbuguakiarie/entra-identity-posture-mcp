from entra_posture_mcp.graph_client import EntraGraphClient, get_shared_graph_client
from entra_posture_mcp.models import ConditionalAccessPolicy, SecurityIssue
from entra_posture_mcp.rules.conditional_access_rules import evaluate_conditional_access_rules


async def execute_scan_conditional_access_gaps(
    graph_client: EntraGraphClient | None = None,
) -> str:
    """Scans Conditional Access policies for MFA admin exclusions and report-only status."""
    if graph_client is None:
        graph_client = get_shared_graph_client()

    raw_policies = await graph_client.get_conditional_access_policies()
    all_issues: list[SecurityIssue] = []

    for policy_data in raw_policies:
        policy = ConditionalAccessPolicy.model_validate(policy_data)
        issues = evaluate_conditional_access_rules(policy)
        all_issues.extend(issues)

    if not all_issues:
        return "✅ Conditional Access scan complete: All policies comply with Zero-Trust standards."

    summary_lines = [f"Found {len(all_issues)} Conditional Access policy gaps:\n"]
    for issue in all_issues:
        summary_lines.append(f"- [{issue.severity}] Policy '{issue.app_name}': {issue.issue}")

    return "\n".join(summary_lines)
