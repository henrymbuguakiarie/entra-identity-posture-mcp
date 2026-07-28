import os
from typing import Any

import msal


class EntraAuthHandler:
    """Handles authentication with Microsoft Entra Identity Platform using MSAL."""

    def __init__(
        self,
        tenant_id: str | None = None,
        client_id: str | None = None,
        cert_path: str | None = None,
        cert_thumbprint: str | None = None,
        authority: str | None = None,
    ):
        self.tenant_id = tenant_id or os.getenv("ENTRA_TENANT_ID")
        self.client_id = client_id or os.getenv("ENTRA_CLIENT_ID")
        self.cert_path = cert_path or os.getenv("ENTRA_CERT_PATH")
        self.cert_thumbprint = cert_thumbprint or os.getenv("ENTRA_CERT_THUMBPRINT")

        if not self.tenant_id or not self.client_id:
            raise ValueError(
                "Tenant ID and Client ID must be provided either as parameters or "
                "environment variables."
            )

        self.authority = authority or f"https://login.microsoftonline.com/{self.tenant_id}"
        self.scopes = ["https://graph.microsoft.com/.default"]

        self.app: msal.ConfidentialClientApplication | None = None

    def _get_client_credentials(self) -> dict[str, Any]:
        """Loads the private key content and constructs MSAL certificate credentials dict."""

        if not self.cert_path or not self.cert_thumbprint:
            raise ValueError(
                "Certificate path and thumbprint must be provided either as parameters or "
                "environment variables."
            )

        with open(self.cert_path, encoding="utf-8") as cert_file:
            private_key = cert_file.read()

        credentials = {"private_key": private_key}
        if self.cert_thumbprint:
            credentials["thumbprint"] = self.cert_thumbprint

        return credentials

    def get_msal_app(self) -> msal.ConfidentialClientApplication:
        """Initializes and returns an MSAL ConfidentialClientApplication instance."""

        if self.app is None:
            credentials = self._get_client_credentials()
            self.app = msal.ConfidentialClientApplication(
                client_id=self.client_id, authority=self.authority, client_credential=credentials
            )
        return self.app

    def acquire_token(self) -> dict[str, Any]:
        """Acquires an access token using the client credentials flow."""

        app = self.get_msal_app()
        result = app.acquire_token_for_client(scopes=self.scopes)

        if "access_token" not in result:
            error_description = result.get("error_description", "Unknown error")
            raise RuntimeError(f"Failed to acquire token: {error_description}")

        return result
