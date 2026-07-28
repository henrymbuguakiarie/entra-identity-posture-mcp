from typing import Literal


async def execute_revoke_or_disable_app_registration(
    app_id: str,
    action: Literal["disable_sign_in", "remove_credential", "remove_permission"],
    key_id: str | None = None,
) -> str:
    """Generates dry-run Azure CLI / PowerShell command to remediate an app registration issue."""
    if action == "disable_sign_in":
        cmd = (
            "# PowerShell (MgGraph): Disable user sign-in\n"
            f"Update-MgServicePrincipal -ServicePrincipalId {app_id} -AccountEnabled:$false"
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
