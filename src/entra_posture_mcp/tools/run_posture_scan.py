import asyncio

from entra_posture_mcp.graph_client import EntraGraphClient, get_shared_graph_client
from entra_posture_mcp.models import PostureScanResult, ScanMetadata, SecurityIssue, Severity
from entra_posture_mcp.resources import update_latest_scan_cache
from entra_posture_mcp.rules.app_registration_rules import RULE_VERSION as APP_RULE_VERSION
from entra_posture_mcp.rules.conditional_access_rules import RULE_VERSION as CA_RULE_VERSION
from entra_posture_mcp.tools.audit_app_registrations import (
    fetch_app_registration_issues,
    format_app_registration_summary,
)
from entra_posture_mcp.tools.scan_conditional_access_gaps import (
    fetch_conditional_access_issues,
    format_conditional_access_summary,
)


def _filter_issues(
    issues: list[SecurityIssue],
    severity: Severity | None,
    rule_id: str | None,
    app_id: str | None,
) -> list[SecurityIssue]:
    """Applies optional severity/rule_id/app_id filters to a combined issue list."""
    filtered = issues
    if severity:
        filtered = [i for i in filtered if i.severity == severity]
    if rule_id:
        filtered = [i for i in filtered if i.rule_id == rule_id]
    if app_id:
        filtered = [i for i in filtered if i.app_id == app_id]
    return filtered


def _format_combined_summary(filtered: list[SecurityIssue], total: int, has_filters: bool) -> str:
    """Formats the merged, optionally filtered findings into a human-readable summary."""
    if not filtered:
        if has_filters:
            return "Posture scan complete: No findings matched the given filters."
        return (
            "Posture scan complete: No security issues detected across app "
            "registrations or Conditional Access policies."
        )

    summary_lines = [f"Found {len(filtered)} posture issues (of {total} total):\n"]
    for issue in filtered:
        summary_lines.append(
            f"- [{issue.severity}] {issue.rule_id} | {issue.app_name}: {issue.issue}"
        )

    return "\n".join(summary_lines)


async def execute_run_posture_scan(
    imminent_expiry_days: int = 30,
    excessive_lifespan_days: int = 180,
    severity: Severity | None = None,
    rule_id: str | None = None,
    app_id: str | None = None,
    graph_client: EntraGraphClient | None = None,
) -> PostureScanResult:
    """Runs the app registration and Conditional Access scans concurrently, updates the
    combined entra://posture/latest resource cache (one entry per category), and returns
    one merged, optionally filtered PostureScanResult instead of requiring an agent to
    call and combine two tools itself.
    """
    if graph_client is None:
        graph_client = get_shared_graph_client()

    app_issues, ca_issues = await asyncio.gather(
        fetch_app_registration_issues(imminent_expiry_days, excessive_lifespan_days, graph_client),
        fetch_conditional_access_issues(graph_client),
    )

    tenant_id = graph_client.auth_handler.tenant_id

    update_latest_scan_cache(
        "app_registration_issues",
        PostureScanResult(
            metadata=ScanMetadata(tenant_id=tenant_id, rule_version=APP_RULE_VERSION),
            issues=app_issues,
            summary=format_app_registration_summary(app_issues),
        ),
    )
    update_latest_scan_cache(
        "conditional_access_issues",
        PostureScanResult(
            metadata=ScanMetadata(tenant_id=tenant_id, rule_version=CA_RULE_VERSION),
            issues=ca_issues,
            summary=format_conditional_access_summary(ca_issues),
        ),
    )

    all_issues = app_issues + ca_issues
    filtered = _filter_issues(all_issues, severity, rule_id, app_id)
    has_filters = bool(severity or rule_id or app_id)

    return PostureScanResult(
        metadata=ScanMetadata(
            tenant_id=tenant_id,
            rule_version=f"app:{APP_RULE_VERSION};ca:{CA_RULE_VERSION}",
        ),
        issues=filtered,
        summary=_format_combined_summary(filtered, len(all_issues), has_filters),
    )
