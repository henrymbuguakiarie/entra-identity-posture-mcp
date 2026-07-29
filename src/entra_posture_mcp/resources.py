from typing import Literal

from pydantic import BaseModel

from entra_posture_mcp.models import PostureScanResult, ScanMetadata, SecurityIssue

ScanCategory = Literal["app_registration_issues", "conditional_access_issues"]


class ScanCacheEntry(BaseModel):
    """Findings and scan metadata cached for one scan category."""

    metadata: ScanMetadata
    issues: list[SecurityIssue]


class PostureCache(BaseModel):
    """Combined in-memory posture cache exposed via the entra://posture/latest resource."""

    status: Literal["no_scans_run", "completed"] = "no_scans_run"
    app_registration_issues: ScanCacheEntry | None = None
    conditional_access_issues: ScanCacheEntry | None = None


_latest_scan_cache = PostureCache()


def update_latest_scan_cache(category: ScanCategory, result: PostureScanResult) -> None:
    """Updates one category of the in-memory scan cache with the latest scan result.

    Both `audit_app_registrations` and `scan_conditional_access_gaps` (and
    `run_posture_scan`, for both categories) call this with their own category so
    the combined `entra://posture/latest` resource always reflects the most recent
    findings from each scan type, instead of only the last scan that happened to run.
    """
    entry = ScanCacheEntry(metadata=result.metadata, issues=result.issues)
    setattr(_latest_scan_cache, category, entry)
    _latest_scan_cache.status = "completed"


def get_latest_scan_json() -> str:
    """Returns the cached scan results as formatted JSON text for the MCP Resource."""
    return _latest_scan_cache.model_dump_json(indent=2)
