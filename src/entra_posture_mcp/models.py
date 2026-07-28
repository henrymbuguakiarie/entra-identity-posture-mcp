from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class SecurityIssue(BaseModel):
    """Represents a security finding or policy violation."""

    app_id: str = Field(...,
                        description="The unique identifier of the application.")
    app_name: str = Field(..., description="The name of the application.")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(
        ..., description="Severity level."
    )
    rule_id: str = Field(...,
                         description="The unique identifier of the rule that was violated.")
    issue: str = Field(...,
                       description="A brief description of the security issue.")
    recommendation: str = Field(...,
                                description="Recommended action to remediate the issue.")
    remediation_command: str | None = Field(
        default=None, description="Command or steps to remediate the issue."
    )


class KeyCredential(BaseModel):
    """Represents a key credential associated with an application."""

    key_id: str = Field(
        default="", alias="keyId", description="The unique identifier of the key credential."
    )
    start_date_time: datetime | None = Field(
        default=None,
        alias="startDateTime",
        description="The start date and time of the key credential.",
    )
    end_date_time: datetime | None = Field(
        default=None,
        alias="endDateTime",
        description="The end date and time of the key credential.",
    )
    usage: str = Field(
        default="", description="The intended usage of the key credential.")
    type: str = Field(
        default="", description="The type of the key credential.")


class PasswordCredential(BaseModel):
    """Represents a password credential associated with an application."""

    key_id: str = Field(
        default="",
        alias="keyId",
        description="The unique identifier of the password credential.",
    )
    display_name: str = Field(
        default="",
        alias="displayName",
        description="The display name of the password credential.",
    )
    start_date_time: datetime | None = Field(
        default=None,
        alias="startDateTime",
        description="The start date and time of the password credential.",
    )
    end_date_time: datetime | None = Field(
        default=None,
        alias="endDateTime",
        description="The end date and time of the password credential.",
    )


class RequiredResourceAccess(BaseModel):
    """Represents the required resource access for an application."""

    resource_app_id: str = Field(
        default="",
        alias="resourceAppId",
        description="The unique identifier of the resource application.",
    )
    resource_access: list[dict] = Field(
        default_factory=list,
        alias="resourceAccess",
        description="A list of resource access permissions required by the application.",
    )


class WebApplication(BaseModel):
    """Represents the web platform settings for an application registration."""

    redirect_uris: list[str] = Field(
        default_factory=list,
        alias="redirectUris",
        description="Redirect URIs configured for the web platform.",
    )


class AppRegistration(BaseModel):
    """Represents an application registration in the identity platform."""

    id: str = Field(
        ..., description="The unique object identifier of the application registration."
    )
    app_id: str = Field(
        ..., alias="appId", description="The unique application (client) identifier."
    )
    display_name: str = Field(
        ..., alias="displayName", description="The display name of the application."
    )
    sign_in_audience: str = Field(
        default="AzureADMyOrg",
        alias="signInAudience",
        description="The sign-in audience for the application.",
    )
    key_credentials: list[KeyCredential] = Field(
        default_factory=list,
        alias="keyCredentials",
        description="A list of key credentials associated with the application.",
    )
    password_credentials: list[PasswordCredential] = Field(
        default_factory=list,
        alias="passwordCredentials",
        description="A list of password credentials associated with the application.",
    )
    required_resource_access: list[RequiredResourceAccess] = Field(
        default_factory=list,
        alias="requiredResourceAccess",
        description="A list of required resource access permissions for the application.",
    )
    is_fallback_public_client: bool = Field(
        default=False,
        alias="isFallbackPublicClient",
        description="Indicates if the application is a fallback public client.",
    )
    web: WebApplication = Field(
        default_factory=WebApplication,
        alias="web",
        description="Web platform settings, including redirect URIs.",
    )

    @field_validator("is_fallback_public_client", mode="before")
    @classmethod
    def _default_none_to_false(cls, value: bool | None) -> bool:
        """Graph API returns an explicit null for this field on many app registrations."""
        return value if value is not None else False


class ConditionalAccessPolicy(BaseModel):
    """Represents a conditional access policy in the identity platform."""

    id: str = Field(..., description="The unique identifier of the conditional access policy.")
    display_name: str = Field(
        ...,
        alias="displayName",
        description="The display name of the conditional access policy.",
    )
    state: Literal["enabled", "disabled", "enabledForReportingButNotEnforced"] = Field(
        ..., description="The state of the conditional access policy."
    )
    conditions: dict = Field(
        default_factory=dict, description="The conditions under which the policy applies."
    )
    grant_controls: dict = Field(
        default_factory=dict,
        alias="grantControls",
        description="The grant controls associated with the policy.",
    )
