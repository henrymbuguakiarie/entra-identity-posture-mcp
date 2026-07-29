import asyncio
import email.utils
import logging
from datetime import UTC, datetime
from typing import Any

import httpx

from entra_posture_mcp.auth import EntraAuthHandler

logger = logging.getLogger(__name__)

# Transient status codes worth retrying with backoff: rate limiting and server errors.
_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

# Explicit request timeout: 10s to establish a connection, 30s total per request,
# so a slow/unresponsive Graph endpoint can't hang a tool call indefinitely.
_DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


def _parse_retry_after(value: str | None) -> float | None:
    """Parses a Retry-After header (either delay-seconds or an HTTP-date) into seconds.

    Returns None if the header is absent or cannot be parsed, so callers can fall
    back to exponential backoff.
    """
    if not value:
        return None
    if value.isdigit():
        return float(value)
    try:
        parsed = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return max((parsed - datetime.now(UTC)).total_seconds(), 0.0)


class EntraGraphClient:
    """Client for interacting with Microsoft Entra Identity Platform Graph API."""

    def __init__(self, auth_handler: EntraAuthHandler):
        self.auth_handler = auth_handler
        self.base_url = "https://graph.microsoft.com/v1.0"
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        """Returns a lazily-created HTTP client reused across requests instead of
        opening a new connection pool for every call.
        """
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT)
        return self._client

    async def aclose(self) -> None:
        """Closes the underlying HTTP client, if one was created."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get_headers(self) -> dict[str, str]:
        """Fetches the authorization headers with a valid access token and builds headers."""

        token = self.auth_handler.acquire_token()
        return {
            "Authorization": f"Bearer {token['access_token']}",
            "Content-Type": "application/json",
            "ConsistencyLevel": "eventual",
        }

    async def get_paginated_data(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        max_retries: int = 3,
    ) -> list[dict[str, Any]]:
        """Fetches paginated data from the specified Graph API endpoint.

        Retries transient failures (429 rate limiting, 5xx server errors, and
        network-level errors) with exponential backoff, up to `max_retries` per
        page. Non-retryable 4xx errors raise immediately.
        """
        headers = await self._get_headers()
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        all_data = []
        client = self._get_client()

        while url:
            retries = 0
            while True:
                try:
                    response = await client.get(url, headers=headers, params=params)
                except httpx.RequestError as exc:
                    retries += 1
                    if retries > max_retries:
                        raise
                    logger.warning(
                        "Network error calling %s (attempt %d/%d): %s",
                        url,
                        retries,
                        max_retries,
                        exc,
                    )
                    await asyncio.sleep(2**retries)
                    continue

                if response.status_code in _RETRYABLE_STATUS_CODES:
                    retries += 1
                    if retries > max_retries:
                        response.raise_for_status()
                    wait_seconds = _parse_retry_after(response.headers.get("Retry-After"))
                    if wait_seconds is None:
                        wait_seconds = 2**retries
                    logger.warning(
                        "Retryable status %d calling %s (attempt %d/%d), waiting %.1fs",
                        response.status_code,
                        url,
                        retries,
                        max_retries,
                        wait_seconds,
                    )
                    await asyncio.sleep(wait_seconds)
                    continue

                response.raise_for_status()
                break

            data = response.json()
            all_data.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            params = None

        return all_data

    async def get_app_registrations(self) -> list[dict[str, Any]]:
        """Fetches all application registrations from Microsoft Entra Identity Platform."""
        select_fields = (
            "id,appId,displayName,signInAudience,keyCredentials,passwordCredentials,"
            "requiredResourceAccess,isFallbackPublicClient,web"
        )
        endpoint = f"/applications?$select={select_fields}"
        return await self.get_paginated_data(endpoint)

    async def get_service_principals(self) -> list[dict[str, Any]]:
        """Fetches all service principals from Microsoft Entra Identity Platform."""
        select_fields = "id,appId,displayName,servicePrincipalType,appOwnerOrganizationId"
        endpoint = f"/servicePrincipals?$select={select_fields}"
        return await self.get_paginated_data(endpoint)

    async def get_conditional_access_policies(self) -> list[dict[str, Any]]:
        """Fetches all conditional access policies from Microsoft Entra Identity Platform."""
        select_fields = "id,displayName,state,conditions,grantControls"
        endpoint = f"/identity/conditionalAccess/policies?$select={select_fields}"
        return await self.get_paginated_data(endpoint)


_shared_graph_client: EntraGraphClient | None = None


def get_shared_graph_client() -> EntraGraphClient:
    """Returns a process-wide singleton `EntraGraphClient`.

    Tool invocations share one instance instead of each creating its own
    `EntraAuthHandler`/`EntraGraphClient`, so the certificate is read and MSAL
    is initialized once per server process rather than once per tool call.
    """
    global _shared_graph_client
    if _shared_graph_client is None:
        _shared_graph_client = EntraGraphClient(auth_handler=EntraAuthHandler())
    return _shared_graph_client


async def aclose_shared_graph_client() -> None:
    """Closes the shared `EntraGraphClient`, if one was ever created.

    Unlike calling `get_shared_graph_client().aclose()`, this does NOT construct
    a new client (and its `EntraAuthHandler`, which requires tenant/client
    credentials) just to close it — safe to call unconditionally on shutdown,
    including in environments with no Graph credentials configured (e.g. CI).
    """
    global _shared_graph_client
    if _shared_graph_client is not None:
        await _shared_graph_client.aclose()
        _shared_graph_client = None
