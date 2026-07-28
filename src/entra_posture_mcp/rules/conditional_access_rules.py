from entra_posture_mcp.models import ConditionalAccessPolicy, SecurityIssue

# Well-known Directory Role IDs for high-privilege admins (Global Admin, Privileged Role Admin)
HIGH_PRIVILEGE_ADMIN_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
}


def evaluate_conditional_access_rules(
    policy: ConditionalAccessPolicy,
) -> list[SecurityIssue]:
    """Evaluates Conditional Access policies against Zero-Trust standards."""
    issues: list[SecurityIssue] = []

    # Check for Report-Only policies
    if policy.state == "enabledForReportingButNotEnforced":
        issues.append(
            SecurityIssue(
                app_id=policy.id,
                app_name=policy.display_name,
                severity="MEDIUM",
                rule_id="CA_REPORT_ONLY_MODE",
                issue=(
                    f"Conditional Access policy '{policy.display_name}' is in "
                    "Report-Only mode."
                ),
                recommendation=(
                    "Transition policy state from "
                    "'enabledForReportingButNotEnforced' to 'enabled' after "
                    "monitoring."
                ),
                remediation_command=(
                    "# PowerShell (MgGraph):\n"
                    "Update-MgIdentityConditionalAccessPolicy "
                    f"-ConditionalAccessPolicyId '{policy.id}' -State 'enabled'"
                ),
            )
        )

    # Check for Admin Exclusions from MFA
    users_cond = policy.conditions.get("users", {})
    excluded_roles = users_cond.get("excludeRoles", [])

    flagged_roles = [
        HIGH_PRIVILEGE_ADMIN_ROLES[r]
        for r in excluded_roles
        if r in HIGH_PRIVILEGE_ADMIN_ROLES
    ]
    if flagged_roles:
        issues.append(
            SecurityIssue(
                app_id=policy.id,
                app_name=policy.display_name,
                severity="CRITICAL",
                rule_id="CA_ADMIN_MFA_EXCLUSION",
                issue=(
                    f"Policy excludes privileged admin roles ({', '.join(flagged_roles)}) "
                    "from enforcement."
                ),
                recommendation=(
                    "Remove Global Administrators and Privileged Role Admins "
                    "from policy exclusion lists."
                ),
                remediation_command=(
                    f"# Review exclusions on CA Policy ID: {policy.id}\n"
                    "Get-MgIdentityConditionalAccessPolicy "
                    f"-ConditionalAccessPolicyId '{policy.id}'"
                ),
            )
        )

    return issues
