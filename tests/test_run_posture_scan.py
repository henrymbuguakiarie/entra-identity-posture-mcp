from unittest.mock import MagicMock

import pytest
import respx
from httpx import Response

from entra_posture_mcp.auth import EntraAuthHandler
from entra_posture_mcp.graph_client import EntraGraphClient
from entra_posture_mcp.resources import _latest_scan_cache
from entra_posture_mcp.tools.audit_app_registrations import execute_audit_app_registrations
from entra_posture_mcp.tools.run_posture_scan import execute_run_posture_scan
from entra_posture_mcp.tools.scan_conditional_access_gaps import (
    execute_scan_conditional_access_gaps,
)

APP_RESPONSE = {
    "value": [
        {
            "id": "obj-1",
            "appId": "client-1",
            "displayName": "Risky App",
            "web": {"redirectUris": ["http://insecure.example.com"]},
        }
    ]
}

CA_RESPONSE = {
    "value": [
        {
            "id": "ca-1",
            "displayName": "Report Only Policy",
            "state": "enabledForReportingButNotEnforced",
        }
    ]
}


@pytest.fixture
def mock_auth_handler():
    handler = MagicMock(spec=EntraAuthHandler)
    handler.acquire_token.return_value = {"access_token": "mock_access_token_123"}
    handler.tenant_id = "tenant-123"
    return handler


@pytest.fixture(autouse=True)
def reset_cache():
    """Resets the module-level posture cache so tests don't leak state into each other."""
    _latest_scan_cache.status = "no_scans_run"
    _latest_scan_cache.app_registration_issues = None
    _latest_scan_cache.conditional_access_issues = None
    yield
    _latest_scan_cache.status = "no_scans_run"
    _latest_scan_cache.app_registration_issues = None
    _latest_scan_cache.conditional_access_issues = None


def _mock_graph_endpoints():
    respx.get("https://graph.microsoft.com/v1.0/applications").mock(
        return_value=Response(200, json=APP_RESPONSE)
    )
    respx.get("https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies").mock(
        return_value=Response(200, json=CA_RESPONSE)
    )


@pytest.mark.asyncio
@respx.mock
async def test_run_posture_scan_combines_both_categories(mock_auth_handler):
    _mock_graph_endpoints()

    client = EntraGraphClient(auth_handler=mock_auth_handler)
    result = await execute_run_posture_scan(graph_client=client)

    rule_ids = {issue.rule_id for issue in result.issues}
    assert "DANGEROUS_REDIRECT_URI" in rule_ids
    assert "CA_REPORT_ONLY_MODE" in rule_ids
    assert result.metadata.tenant_id == "tenant-123"


@pytest.mark.asyncio
@respx.mock
async def test_run_posture_scan_updates_both_cache_categories(mock_auth_handler):
    _mock_graph_endpoints()

    client = EntraGraphClient(auth_handler=mock_auth_handler)
    await execute_run_posture_scan(graph_client=client)

    assert _latest_scan_cache.status == "completed"
    assert _latest_scan_cache.app_registration_issues is not None
    assert _latest_scan_cache.conditional_access_issues is not None
    assert len(_latest_scan_cache.app_registration_issues.issues) == 1
    assert len(_latest_scan_cache.conditional_access_issues.issues) == 1


@pytest.mark.asyncio
@respx.mock
async def test_run_posture_scan_severity_filter_excludes_all(mock_auth_handler):
    _mock_graph_endpoints()

    client = EntraGraphClient(auth_handler=mock_auth_handler)
    result = await execute_run_posture_scan(severity="LOW", graph_client=client)

    assert result.issues == []
    assert "No findings matched the given filters" in result.summary


@pytest.mark.asyncio
@respx.mock
async def test_run_posture_scan_rule_id_filter(mock_auth_handler):
    _mock_graph_endpoints()

    client = EntraGraphClient(auth_handler=mock_auth_handler)
    result = await execute_run_posture_scan(rule_id="CA_REPORT_ONLY_MODE", graph_client=client)

    assert len(result.issues) == 1
    assert result.issues[0].rule_id == "CA_REPORT_ONLY_MODE"


@pytest.mark.asyncio
@respx.mock
async def test_run_posture_scan_app_id_filter(mock_auth_handler):
    _mock_graph_endpoints()

    client = EntraGraphClient(auth_handler=mock_auth_handler)
    result = await execute_run_posture_scan(app_id="client-1", graph_client=client)

    assert len(result.issues) == 1
    assert result.issues[0].app_id == "client-1"


@pytest.mark.asyncio
@respx.mock
async def test_individual_scans_do_not_overwrite_each_others_cache_entry(mock_auth_handler):
    _mock_graph_endpoints()

    client = EntraGraphClient(auth_handler=mock_auth_handler)
    await execute_audit_app_registrations(graph_client=client)
    await execute_scan_conditional_access_gaps(graph_client=client)

    assert _latest_scan_cache.app_registration_issues is not None
    assert _latest_scan_cache.conditional_access_issues is not None
    assert len(_latest_scan_cache.app_registration_issues.issues) == 1
    assert len(_latest_scan_cache.conditional_access_issues.issues) == 1
