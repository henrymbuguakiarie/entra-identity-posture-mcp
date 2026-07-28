from unittest.mock import MagicMock

import pytest
import respx
from httpx import Response

from entra_posture_mcp.auth import EntraAuthHandler
from entra_posture_mcp.graph_client import EntraGraphClient


@pytest.fixture
def mock_auth_handler():
    handler = MagicMock(spec=EntraAuthHandler)
    handler.acquire_token.return_value = {"access_token": "mock_access_token_123"}
    return handler


@pytest.mark.asyncio
@respx.mock
async def test_get_paginated_data_single_page(mock_auth_handler):
    respx.get("https://graph.microsoft.com/v1.0/applications").mock(
        return_value=Response(
            200,
            json={"value": [{"id": "1", "displayName": "App One"}]},
        )
    )

    client = EntraGraphClient(auth_handler=mock_auth_handler)
    results = await client.get_paginated_data("/applications")

    assert len(results) == 1
    assert results[0]["displayName"] == "App One"


@pytest.mark.asyncio
@respx.mock
async def test_get_paginated_data_multiple_pages(mock_auth_handler):
    # respx matches on path regardless of query string, so a single route
    # registered on the base path intercepts both requests. Use side_effect
    # to return page 1 then page 2 in sequence.
    respx.get("https://graph.microsoft.com/v1.0/applications").mock(
        side_effect=[
            Response(
                200,
                json={
                    "value": [{"id": "1", "displayName": "App One"}],
                    "@odata.nextLink": "https://graph.microsoft.com/v1.0/applications?$skiptoken=abc",
                },
            ),
            Response(
                200,
                json={"value": [{"id": "2", "displayName": "App Two"}]},
            ),
        ]
    )

    client = EntraGraphClient(auth_handler=mock_auth_handler)
    results = await client.get_paginated_data("/applications")

    assert len(results) == 2
    assert results[0]["displayName"] == "App One"
    assert results[1]["displayName"] == "App Two"
