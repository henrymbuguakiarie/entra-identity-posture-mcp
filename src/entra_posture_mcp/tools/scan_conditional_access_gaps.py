from entra_posture_mcp.graph_client import EntraGraphClient, get_shared_graph_client
from entra_posture_mcp.models import (
    ConditionalAccessPolicy,
    PostureScanResult,
    ScanMetadata,
    SecurityIssue,
)
from entra_posture_mcp.resources import update_latest_scan_cache
from entra_posture_mcp.rules.conditional_access_rules import (
    RULE_VERSION,
    evaluate_conditional_access_rules,
)


async def fetch_conditional_access_issues(graph_client: EntraGraphClient) -> list[SecurityIssue]:
    """Fetches Conditional Access policies from Graph and evaluates them against the rule set.

    Shared by `execute_scan_conditional_access_gaps` and `execute_run_posture_scan` so both
    can access the raw, structured findings instead of only the formatted text summary.
    """
    raw_policies = await graph_client.get_conditional_access_policies()
    all_issues: list[SecurityIssue] = []

    for policy_data in raw_policies:
        policy = ConditionalAccessPolicy.model_validate(policy_data)
        issues = evaluate_conditional_access_rules(policy)
        all_issues.extend(issues)

    return all_issues


def format_conditional_access_summary(all_issues: list[SecurityIssue]) -> str:
    """Formats Conditional Access findings into the human-readable tool summary text."""
    if not all_issues:
        return "✅ Conditional Access scan complete: All policies comply with Zero-Trust standards."

    summary_lines = [f"Found {len(all_issues)} Conditional Access policy gaps:\n"]
    for issue in all_issues:
        summary_lines.append(f"- [{issue.severity}] Policy '{issue.app_name}': {issue.issue}")

    return "\n".join(summary_lines)


async def execute_scan_conditional_access_gaps(
    graph_client: EntraGraphClient | None = None,
) -> PostureScanResult:
    """Scans Conditional Access policies for MFA admin exclusions and report-only status.

    Returns structured findings (metadata + issues) alongside a human-readable
    summary, and updates the shared entra://posture/latest resource cache.
    """
    if graph_client is None:
        graph_client = get_shared_graph_client()

    all_issues = await fetch_conditional_access_issues(graph_client)

    result = PostureScanResult(
        metadata=ScanMetadata(
            tenant_id=graph_client.auth_handler.tenant_id,
            rule_version=RULE_VERSION,
        ),
        issues=all_issues,
        summary=format_conditional_access_summary(all_issues),
    )

    update_latest_scan_cache("conditional_access_issues", result)

    return result
