import asyncio
import logging
from typing import Any

import httpx

from entra_posture_mcp.auth import EntraAuthHandler

logger = logging.getLogger(__name__)

# Transient status codes worth retrying with backoff: rate limiting and server errors.
_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


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
            self._client = httpx.AsyncClient()
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
                    logger.warning(
                        "Retryable status %d calling %s (attempt %d/%d)",
                        response.status_code,
                        url,
                        retries,
                        max_retries,
                    )
                    await asyncio.sleep(2**retries)
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
        _shared_graph_client = EntraGraphClient(
            auth_handler=EntraAuthHandler())
    return _shared_graph_client
