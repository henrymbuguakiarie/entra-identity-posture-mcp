import os
from datetime import UTC, datetime

from entra_posture_mcp.models import AppRegistration, SecurityIssue

# High-risk permission IDs and names in Microsoft Graph
HIGH_RISK_GRAPH_PERMISSIONS = {
    # Directory.ReadWrite.All
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
    # RoleManagement.ReadWrite.Directory
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    # AppRoleAssignment.ReadWrite.All
    "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
    # Application.ReadWrite.All
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
}

MULTI_TENANT_AUDIENCES = {"AzureADMultipleOrgs",
                          "AzureADandPersonalMicrosoftAccount"}


def evaluate_app_registration_rules(
    app: AppRegistration,
    imminent_expiry_days: int | None = None,
    excessive_lifespan_days: int | None = None,
) -> list[SecurityIssue]:
    """Evaluates an AppRegistration model against security rules and returns findings."""
    issues: list[SecurityIssue] = []
    now = datetime.now(UTC)

    imminent_threshold = imminent_expiry_days or int(
        os.getenv("IMMINENT_EXPIRATION_DAYS", "30")
    )
    excessive_threshold = excessive_lifespan_days or int(
        os.getenv("EXCESSIVE_LIFESPAN_DAYS", "180")
    )

    # --- Rule 1 & 2: Credential Expiration & Excessive Lifespan ---
    all_creds = app.key_credentials + app.password_credentials
    for cred in all_creds:
        if cred.end_date_time:
            end_dt = (
                cred.end_date_time
                if cred.end_date_time.tzinfo
                else cred.end_date_time.replace(tzinfo=UTC)
            )
            days_until_expiry = (end_dt - now).days

            if 0 <= days_until_expiry <= imminent_threshold:
                issues.append(
                    SecurityIssue(
                        app_id=app.app_id,
                        app_name=app.display_name,
                        severity="HIGH",
                        rule_id="IMMINENT_EXPIRATION",
                        issue=(
                            f"Credential key_id '{cred.key_id}' expires in "
                            f"{days_until_expiry} days."
                        ),
                        recommendation=(
                            "Rotate this credential before expiration to prevent "
                            "pipeline failure."
                        ),
                        remediation_command=(
                            "# Azure CLI: Rotate secret\n"
                            f"az ad app credential reset --id {app.app_id}"
                        ),
                    )
                )

        if cred.start_date_time and cred.end_date_time:
            start_dt = (
                cred.start_date_time
                if cred.start_date_time.tzinfo
                else cred.start_date_time.replace(tzinfo=UTC)
            )
            end_dt = (
                cred.end_date_time
                if cred.end_date_time.tzinfo
                else cred.end_date_time.replace(tzinfo=UTC)
            )
            total_lifespan_days = (end_dt - start_dt).days

            if total_lifespan_days > excessive_threshold:
                issues.append(
                    SecurityIssue(
                        app_id=app.app_id,
                        app_name=app.display_name,
                        severity="MEDIUM",
                        rule_id="EXCESSIVE_LIFESPAN",
                        issue=(
                            f"Credential key_id '{cred.key_id}' has an excessive "
                            f"lifespan of {total_lifespan_days} days."
                        ),
                        recommendation=(
                            "Enforce Zero-Trust credential hygiene by capping "
                            f"lifespans to $\\le$ {excessive_threshold} days."
                        ),
                        remediation_command=(
                            "# Azure CLI: Revoke long-lived credential\n"
                            f"az ad app credential delete --id {app.app_id} "
                            f"--key-id {cred.key_id}"
                        ),
                    )
                )

    # --- Rule 3 & 5: High-Risk Scopes & Multi-Tenant Combinations ---
    found_high_risk_scopes: list[str] = []
    for resource in app.required_resource_access:
        for access in resource.resource_access:
            res_id = access.get("id")
            if res_id in HIGH_RISK_GRAPH_PERMISSIONS:
                found_high_risk_scopes.append(
                    HIGH_RISK_GRAPH_PERMISSIONS[res_id])

    if found_high_risk_scopes:
        is_multi_tenant = app.sign_in_audience in MULTI_TENANT_AUDIENCES
        severity = "CRITICAL" if is_multi_tenant else "HIGH"
        issue_msg = (
            "App has over-privileged Graph permissions: "
            f"{', '.join(found_high_risk_scopes)}."
        )
        if is_multi_tenant:
            issue_msg += (
                f" Combined with multi-tenant audience '{app.sign_in_audience}'."
            )

        issues.append(
            SecurityIssue(
                app_id=app.app_id,
                app_name=app.display_name,
                severity=severity,
                rule_id="HIGH_RISK_PERMISSIONS",
                issue=issue_msg,
                recommendation=(
                    "Remove unneeded administrative permissions and apply "
                    "principle of least privilege."
                ),
                remediation_command=(
                    "# PowerShell (MgGraph): Remove high-risk permissions\n"
                    f"# Review and update permissions for App Object ID: {app.id}\n"
                    f"Update-MgApplication -ApplicationId {app.id}"
                ),
            )
        )

    # --- Rule 4: Dangerous Redirect URIs & Public Client Config ---
    risky_uris = [
        uri
        for uri in app.web.redirect_uris
        if uri.startswith("http://") or "*" in uri
    ]
    if risky_uris:
        issues.append(
            SecurityIssue(
                app_id=app.app_id,
                app_name=app.display_name,
                severity="HIGH",
                rule_id="DANGEROUS_REDIRECT_URI",
                issue=f"Insecure redirect URIs detected: {', '.join(risky_uris)}.",
                recommendation=(
                    "Enforce HTTPS for all redirect URIs and remove wildcards."
                ),
                remediation_command=(
                    "# PowerShell (MgGraph): Update redirect URIs\n"
                    f"Update-MgApplication -ApplicationId {app.id} -Web "
                    "@{{ RedirectUris = @('https://your-secure-domain/callback') }}"
                ),
            )
        )

    return issues
