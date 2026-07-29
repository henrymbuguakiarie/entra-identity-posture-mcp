from entra_posture_mcp.graph_client import EntraGraphClient, get_shared_graph_client
from entra_posture_mcp.models import AppRegistration, SecurityIssue
from entra_posture_mcp.resources import update_latest_scan_cache
from entra_posture_mcp.rules.app_registration_rules import evaluate_app_registration_rules


async def fetch_app_registration_issues(
    imminent_expiry_days: int,
    excessive_lifespan_days: int,
    graph_client: EntraGraphClient,
) -> list[SecurityIssue]:
    """Fetches app registrations from Graph and evaluates them against the rule set.

    Shared by `execute_audit_app_registrations` and `execute_run_posture_scan` so both
    can access the raw, structured findings instead of only the formatted text summary.
    """
    raw_apps = await graph_client.get_app_registrations()
    all_issues: list[SecurityIssue] = []

    for app_data in raw_apps:
        app = AppRegistration.model_validate(app_data)
        issues = evaluate_app_registration_rules(
            app,
            imminent_expiry_days=imminent_expiry_days,
            excessive_lifespan_days=excessive_lifespan_days,
        )
        all_issues.extend(issues)

    return all_issues


def format_app_registration_summary(all_issues: list[SecurityIssue]) -> str:
    """Formats app registration findings into the human-readable tool summary text."""
    if not all_issues:
        return "Audit complete: No app registration security issues detected."

    summary_lines = [f"Found {len(all_issues)} app registration security issues:\n"]
    for issue in all_issues:
        summary_lines.append(
            f"- [{issue.severity}] {issue.app_name} ({issue.app_id}): {issue.issue}"
        )

    return "\n".join(summary_lines)


async def execute_audit_app_registrations(
    imminent_expiry_days: int = 30,
    excessive_lifespan_days: int = 180,
    graph_client: EntraGraphClient | None = None,
) -> str:
    """Scans Entra ID app registrations for expiring secrets, risky scopes, and redirect URIs."""
    if graph_client is None:
        graph_client = get_shared_graph_client()

    all_issues = await fetch_app_registration_issues(
        imminent_expiry_days, excessive_lifespan_days, graph_client
    )

    update_latest_scan_cache(
        "app_registration_issues",
        [i.model_dump() for i in all_issues],
        tenant_id=graph_client.auth_handler.tenant_id,
    )

    return format_app_registration_summary(all_issues)
