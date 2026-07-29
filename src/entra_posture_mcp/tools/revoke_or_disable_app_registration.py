from typing import Literal


async def execute_revoke_or_disable_app_registration(
    app_id: str,
    action: Literal[
        "disable_sign_in", "remove_credential", "remove_permission", "rotate_credential"
    ],
    key_id: str | None = None,
) -> str:
    """Generates dry-run Azure CLI / PowerShell command to remediate an app registration issue."""
    if action == "disable_sign_in":
        cmd = (
            "# PowerShell (MgGraph): Disable user sign-in\n"
            "# NOTE: -ServicePrincipalId expects the Service Principal's object ID,\n"
            "# not the application (client) ID. If app_id below is a client ID,\n"
            "# resolve it first, e.g.:\n"
            f"# (Get-MgServicePrincipal -Filter \"appId eq '{app_id}'\").Id\n"
            f"Update-MgServicePrincipal -ServicePrincipalId {app_id} -AccountEnabled:$false"
        )
    elif action == "rotate_credential":
        cmd = (
            "# Azure CLI: Rotate secret\n"
            "# NOTE: By default this command clears ALL existing password/certificate\n"
            "# credentials on the app and creates one new one. Add --append to add a\n"
            "# new credential without removing existing ones (recommended for zero-\n"
            "# downtime rotation of a single expiring credential).\n"
            f"az ad app credential reset --id {app_id} --append"
        )
    elif action == "remove_credential":
        if not key_id:
            return "Error: key_id is required when action is 'remove_credential'."
        cmd = (
            "# Azure CLI: Remove client credential\n"
            f"az ad app credential delete --id {app_id} --key-id {key_id}"
        )
    elif action == "remove_permission":
        cmd = (
            "# PowerShell (MgGraph): Review and adjust app permissions\n"
            f"Update-MgApplication -ApplicationId {app_id}"
        )

    return (
        f"🔒 Dry-Run Remediation Output for App ID '{app_id}':\n\n"
        f"```bash\n{cmd}\n```\n"
        "*(Note: Read-only mode active. Run the script manually or via CI pipeline to execute).* "
    )
