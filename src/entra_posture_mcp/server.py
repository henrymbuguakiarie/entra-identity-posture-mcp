from contextlib import asynccontextmanager
from typing import Literal

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from entra_posture_mcp.graph_client import get_shared_graph_client
from entra_posture_mcp.models import PostureScanResult
from entra_posture_mcp.prompts import get_security_triage_prompt
from entra_posture_mcp.resources import get_latest_scan_json
from entra_posture_mcp.tools.audit_app_registrations import (
    execute_audit_app_registrations,
)
from entra_posture_mcp.tools.generate_remediation_plan import (
    execute_generate_remediation_plan,
)
from entra_posture_mcp.tools.revoke_or_disable_app_registration import (
    execute_revoke_or_disable_app_registration,
)
from entra_posture_mcp.tools.run_posture_scan import execute_run_posture_scan
from entra_posture_mcp.tools.scan_conditional_access_gaps import (
    execute_scan_conditional_access_gaps,
)

load_dotenv()


@asynccontextmanager
async def lifespan(_server: FastMCP):
    """Closes the shared Graph HTTP client's connection pool on server shutdown."""
    try:
        yield
    finally:
        await get_shared_graph_client().aclose()


mcp = FastMCP("Entra Identity Posture Guard", lifespan=lifespan)


# --- Register MCP Tools ---
@mcp.tool()
async def audit_app_registrations(
    imminent_expiry_days: int = 30,
    excessive_lifespan_days: int = 180,
) -> PostureScanResult:
    """Scans Entra ID app registrations for expiring secrets, excessive lifespans,
    risky permissions, and insecure redirect URIs. Returns structured findings
    (metadata + issues) alongside a human-readable summary.
    """
    return await execute_audit_app_registrations(
        imminent_expiry_days=imminent_expiry_days,
        excessive_lifespan_days=excessive_lifespan_days,
    )


@mcp.tool()
async def scan_conditional_access_gaps() -> PostureScanResult:
    """Scans Entra Conditional Access policies for admin MFA exclusions and
    policies stuck in report-only mode. Returns structured findings alongside
    a human-readable summary.
    """
    return await execute_scan_conditional_access_gaps()


@mcp.tool()
async def run_posture_scan(
    imminent_expiry_days: int = 30,
    excessive_lifespan_days: int = 180,
    severity: str | None = None,
    rule_id: str | None = None,
    app_id: str | None = None,
) -> PostureScanResult:
    """Runs the app registration and Conditional Access scans concurrently and
    returns one combined, optionally filtered PostureScanResult. Updates the
    shared entra://posture/latest resource cache with both scan categories.
    """
    return await execute_run_posture_scan(
        imminent_expiry_days=imminent_expiry_days,
        excessive_lifespan_days=excessive_lifespan_days,
        severity=severity,
        rule_id=rule_id,
        app_id=app_id,
    )


@mcp.tool()
async def generate_remediation_plan(issues: list[dict]) -> str:
    """Generates a Zero-Trust Markdown security report and dry-run CLI
    remediation commands from findings.
    """
    return await execute_generate_remediation_plan(issues)


@mcp.tool()
async def revoke_or_disable_app_registration(
    app_id: str,
    action: Literal[
        "disable_sign_in", "remove_credential", "remove_permission", "rotate_credential"
    ],
    key_id: str | None = None,
) -> str:
    """Generates dry-run Azure CLI or PowerShell commands to disable sign-in
    or revoke credentials.
    """
    return await execute_revoke_or_disable_app_registration(
        app_id=app_id,
        action=action,
        key_id=key_id,
    )


# --- Register MCP Resource ---
@mcp.resource("entra://posture/latest")
def get_latest_posture_resource() -> str:
    """Provides access to cached JSON results from the most recent identity posture scan."""
    return get_latest_scan_json()


# --- Register MCP Prompt ---
@mcp.prompt()
def security_triage_prompt() -> str:
    """Returns predefined Zero-Trust triage prompt template for natural-language
    agent orchestration.
    """
    return get_security_triage_prompt()


def main():
    """Main entrypoint for stdio MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
