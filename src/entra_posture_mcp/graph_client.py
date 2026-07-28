import asyncio
import logging
from typing import Any

import httpx

from entra_posture_mcp.auth import EntraAuthHandler

logger = logging.getLogger(__name__)


class EntraGraphClient:
    """Client for interacting with Microsoft Entra Identity Platform Graph API."""

    def __init__(self, auth_handler: EntraAuthHandler):
        self.auth_handler = auth_handler
        self.base_url = "https://graph.microsoft.com/v1.0"

    async def _get_headers(self) -> dict[str, str]:
        """Fetches the authorization headers with a valid access token and builds headers."""

        token = self.auth_handler.acquire_token()
        return {
            "Authorization": f"Bearer {token['access_token']}",
            "Content-Type": "application/json",
            "ConsistencyLevel": "eventual"
        }

    async def get_paginated_data(
            self, endpoint: str,
            params: dict[str, Any] | None = None,
            max_retries: int = 3,) -> list[dict[str, Any]]:
        """Fetches paginated data from the specified Graph API endpoint."""
        headers = await self._get_headers()
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        all_data = []
        retries = 0
        async with httpx.AsyncClient() as client:
            while url and retries < max_retries:
                response = await client.get(url, headers=headers, params=params)
                if response.status_code == 429:  # Too Many Requests
                    retries += 1
                    await asyncio.sleep(2 ** retries)
                    continue
                response.raise_for_status()
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
