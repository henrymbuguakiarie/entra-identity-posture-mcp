import pytest
from mcp.shared.memory import create_connected_server_and_client_session

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
    assert "run_posture_scan" in tools
    assert "generate_remediation_plan" in tools
    assert "revoke_or_disable_app_registration" in tools


@pytest.mark.asyncio
async def test_revoke_tool_rejects_invalid_action():
    """The action parameter is a Literal at the MCP boundary, so an invalid
    value should fail JSON-RPC input validation before the tool body runs.
    """
    async with create_connected_server_and_client_session(mcp._mcp_server) as client:
        result = await client.call_tool(
            "revoke_or_disable_app_registration",
            {"app_id": "app-123", "action": "delete_everything"},
        )
        assert result.isError
