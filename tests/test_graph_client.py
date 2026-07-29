from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import respx
from httpx import Response

from entra_posture_mcp.auth import EntraAuthHandler
from entra_posture_mcp.graph_client import EntraGraphClient, _parse_retry_after


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


def test_parse_retry_after_delay_seconds():
    assert _parse_retry_after("5") == 5.0


def test_parse_retry_after_http_date():
    future = datetime.now(UTC) + timedelta(seconds=10)
    seconds = _parse_retry_after(format_datetime(future, usegmt=True))
    assert seconds is not None
    assert 0 <= seconds <= 10


def test_parse_retry_after_missing_or_invalid():
    assert _parse_retry_after(None) is None
    assert _parse_retry_after("") is None
    assert _parse_retry_after("not-a-valid-header") is None


@pytest.mark.asyncio
@respx.mock
async def test_get_paginated_data_retries_429_using_retry_after_header(mock_auth_handler):
    respx.get("https://graph.microsoft.com/v1.0/applications").mock(
        side_effect=[
            Response(429, headers={"Retry-After": "3"}, json={"error": "rate limited"}),
            Response(200, json={"value": [{"id": "1", "displayName": "App One"}]}),
        ]
    )

    client = EntraGraphClient(auth_handler=mock_auth_handler)
    with patch(
        "entra_posture_mcp.graph_client.asyncio.sleep", new_callable=AsyncMock
    ) as mock_sleep:
        results = await client.get_paginated_data("/applications")

    assert len(results) == 1
    mock_sleep.assert_awaited_once_with(3.0)


@pytest.mark.asyncio
@respx.mock
async def test_get_paginated_data_retries_429_falls_back_to_exponential_backoff(
    mock_auth_handler,
):
    # No Retry-After header: should fall back to 2**retries backoff.
    respx.get("https://graph.microsoft.com/v1.0/applications").mock(
        side_effect=[
            Response(429, json={"error": "rate limited"}),
            Response(200, json={"value": [{"id": "1", "displayName": "App One"}]}),
        ]
    )

    client = EntraGraphClient(auth_handler=mock_auth_handler)
    with patch(
        "entra_posture_mcp.graph_client.asyncio.sleep", new_callable=AsyncMock
    ) as mock_sleep:
        results = await client.get_paginated_data("/applications")

    assert len(results) == 1
    mock_sleep.assert_awaited_once_with(2)
