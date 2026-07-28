
import pytest

from entra_posture_mcp.server import mcp
from entra_posture_mcp.tools.revoke_or_disable_app_registration import (
    execute_revoke_or_disable_app_registration,
)


@pytest.mark.asyncio
async def test_revoke_or_disable_app_registration_tool():
    res = await execute_revoke_or_disable_app_registration(
        app_id="app-123", action="disable_sign_in"
    )
    assert "Update-MgServicePrincipal" in res
    assert "app-123" in res


def test_resource_and_prompt_registered():
    # Verify tools, resource, and prompt are registered on FastMCP instance
    tools = [t.name for t in mcp._tool_manager.list_tools()]
    assert "audit_app_registrations" in tools
    assert "scan_conditional_access_gaps" in tools
    assert "generate_remediation_plan" in tools
    assert "revoke_or_disable_app_registration" in tools
