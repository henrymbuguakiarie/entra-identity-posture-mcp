from datetime import UTC, datetime, timedelta

from entra_posture_mcp.models import (
    AppRegistration,
    ConditionalAccessPolicy,
    PasswordCredential,
    RequiredResourceAccess,
)
from entra_posture_mcp.rules.app_registration_rules import (
    evaluate_app_registration_rules,
)
from entra_posture_mcp.rules.conditional_access_rules import (
    evaluate_conditional_access_rules,
)


def test_imminent_expiration_and_excessive_lifespan():
    now = datetime.now(UTC)
    app = AppRegistration(
        id="obj-1",
        appId="client-1",
        displayName="Test App",
        passwordCredentials=[
            # Imminent expiry (expires in 10 days)
            PasswordCredential(
                keyId="k1",
                displayName="Secret 1",
                startDateTime=now - timedelta(days=30),
                endDateTime=now + timedelta(days=10),
            ),
            # Excessive lifespan (365 days lifespan)
            PasswordCredential(
                keyId="k2",
                displayName="Secret 2",
                startDateTime=now - timedelta(days=100),
                endDateTime=now + timedelta(days=265),
            ),
        ],
    )

    issues = evaluate_app_registration_rules(app)
    rule_ids = [i.rule_id for i in issues]

    assert "IMMINENT_EXPIRATION" in rule_ids
    assert "EXCESSIVE_LIFESPAN" in rule_ids


def test_multi_tenant_high_risk_scope_critical():
    app = AppRegistration(
        id="obj-2",
        appId="client-2",
        displayName="Multi Tenant App",
        signInAudience="AzureADMultipleOrgs",
        requiredResourceAccess=[
            RequiredResourceAccess(
                resourceAppId="00000003-0000-0000-c000-000000000000",
                resourceAccess=[
                    {"id": "19dbc75e-c2e2-444c-a770-ec69d8559fc7",
                        "type": "Role"}  # Directory.ReadWrite.All
                ],
            )
        ],
    )

    issues = evaluate_app_registration_rules(app)
    high_risk_issue = next(
        i for i in issues if i.rule_id == "HIGH_RISK_PERMISSIONS")

    assert high_risk_issue.severity == "CRITICAL"
    assert "AzureADMultipleOrgs" in high_risk_issue.issue


def test_conditional_access_report_only_and_admin_exclusion():
    policy = ConditionalAccessPolicy(
        id="ca-1",
        displayName="Strict Admin MFA",
        state="enabledForReportingButNotEnforced",
        conditions={
            "users": {
                # Global Admin
                "excludeRoles": ["62e90394-69f5-4237-9190-012177145e10"]
            }
        },
    )

    issues = evaluate_conditional_access_rules(policy)
    rule_ids = [i.rule_id for i in issues]

    assert "CA_REPORT_ONLY_MODE" in rule_ids
    assert "CA_ADMIN_MFA_EXCLUSION" in rule_ids
