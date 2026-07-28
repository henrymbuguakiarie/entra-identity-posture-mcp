import json
from datetime import UTC
from typing import Any

# Global in-memory cache for the latest scan results
_LATEST_SCAN_CACHE: dict[str, Any] = {
    "status": "no_scans_run",
    "timestamp": None,
    "issues": [],
}


def update_latest_scan_cache(issues: list[dict[str, Any]]) -> None:
    """Updates the in-memory scan cache with latest findings."""
    from datetime import datetime

    _LATEST_SCAN_CACHE["status"] = "completed"
    _LATEST_SCAN_CACHE["timestamp"] = datetime.now(UTC).isoformat()
    _LATEST_SCAN_CACHE["issues"] = issues


def get_latest_scan_json() -> str:
    """Returns the cached scan results as formatted JSON text for the MCP Resource."""
    return json.dumps(_LATEST_SCAN_CACHE, indent=2)
