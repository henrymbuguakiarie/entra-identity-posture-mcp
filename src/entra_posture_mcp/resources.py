import json
from datetime import UTC, datetime
from typing import Any, Literal

ScanCategory = Literal["app_registration_issues", "conditional_access_issues"]

# Global in-memory cache for the latest combined scan results across both scan types.
_LATEST_SCAN_CACHE: dict[str, Any] = {
    "status": "no_scans_run",
    "last_updated": None,
    "tenant_id": None,
    "app_registration_issues": [],
    "conditional_access_issues": [],
}


def update_latest_scan_cache(
    category: ScanCategory,
    issues: list[dict[str, Any]],
    tenant_id: str | None = None,
) -> None:
    """Updates one category of the in-memory scan cache with the latest findings.

    Both `audit_app_registrations` and `scan_conditional_access_gaps` call this with
    their own category so the combined `entra://posture/latest` resource always
    reflects the most recent findings from each scan type, instead of only the
    last scan that happened to run.
    """
    _LATEST_SCAN_CACHE["status"] = "completed"
    _LATEST_SCAN_CACHE["last_updated"] = datetime.now(UTC).isoformat()
    _LATEST_SCAN_CACHE[category] = issues
    if tenant_id is not None:
        _LATEST_SCAN_CACHE["tenant_id"] = tenant_id


def get_latest_scan_json() -> str:
    """Returns the cached scan results as formatted JSON text for the MCP Resource."""
    return json.dumps(_LATEST_SCAN_CACHE, indent=2)
