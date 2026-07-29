from datetime import UTC, datetime, timedelta

from entra_posture_mcp.models import (
    AppRegistration,
    ConditionalAccessPolicy,
    KeyCredential,
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

    imminent = next(i for i in issues if i.rule_id == "IMMINENT_EXPIRATION")
    assert imminent.remediation_action == "rotate_password_credential"
    assert imminent.remediation_params == {"app_id": "client-1"}
    assert imminent.evidence["key_id"] == "k1"
    assert imminent.evidence["credential_type"] == "password"

    excessive = next(i for i in issues if i.rule_id == "EXCESSIVE_LIFESPAN")
    assert excessive.remediation_action == "remove_credential"
    assert excessive.remediation_params == {"app_id": "client-1", "key_id": "k2"}
    assert excessive.evidence["key_id"] == "k2"
    assert excessive.evidence["credential_type"] == "password"


def test_imminent_expiration_certificate_credential_uses_certificate_action():
    now = datetime.now(UTC)
    app = AppRegistration(
        id="obj-1b",
        appId="client-1b",
        displayName="Cert App",
        keyCredentials=[
            KeyCredential(
                keyId="cert-1",
                startDateTime=now - timedelta(days=30),
                endDateTime=now + timedelta(days=10),
                usage="Verify",
                type="AsymmetricX509Cert",
            ),
        ],
    )

    issues = evaluate_app_registration_rules(app)
    imminent = next(i for i in issues if i.rule_id == "IMMINENT_EXPIRATION")

    assert imminent.remediation_action == "rotate_certificate_credential"
    assert imminent.evidence["credential_type"] == "certificate"
    assert "--create-cert" in imminent.remediation_command


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
                    {
                        "id": "19dbc75e-c2e2-444c-a770-ec69d8559fc7",
                        "type": "Role",
                    }  # Directory.ReadWrite.All
                ],
            )
        ],
    )

    issues = evaluate_app_registration_rules(app)
    high_risk_issue = next(i for i in issues if i.rule_id == "HIGH_RISK_PERMISSIONS")

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

    admin_exclusion = next(i for i in issues if i.rule_id == "CA_ADMIN_MFA_EXCLUSION")
    assert admin_exclusion.evidence["policy_id"] == "ca-1"
    assert "Global Administrator" in admin_exclusion.evidence["excluded_roles"]
