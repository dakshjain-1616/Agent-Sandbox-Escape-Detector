"""FastAPI route handlers for the scan API."""

from __future__ import annotations

import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, HTTPException

from src.core.probes.base import ScanReport, ScanRequest, ScanStatus
from src.core.scanner import Scanner

logger = logging.getLogger(__name__)

router = APIRouter()

# In-memory scan store: scan_id -> ScanReport
_scan_store: dict[UUID, ScanReport] = {}
_scanner = Scanner()


@router.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint.

    Returns:
        Status information about the API.
    """
    return {"status": "ok", "version": "1.0.0"}


@router.post("/scan")
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks) -> dict[str, str]:
    """Initiate a new sandbox escape scan.

    Args:
        request: Scan request with target URL, optional API key, and probe selection.
        background_tasks: FastAPI background tasks runner.

    Returns:
        Dictionary with scan_id and status.
    """
    report = ScanReport(
        target_url=request.target_url,
        status=ScanStatus.PENDING,
    )
    _scan_store[report.scan_id] = report

    # Launch scan as a background task
    background_tasks.add_task(_execute_scan, report, request)

    return {"scan_id": str(report.scan_id), "status": "pending"}


@router.get("/results/{scan_id}")
async def get_results(scan_id: UUID) -> ScanReport:
    """Get the results of a scan.

    Args:
        scan_id: UUID of the scan to retrieve.

    Returns:
        Complete ScanReport.

    Raises:
        HTTPException: If scan_id is not found.
    """
    report = _scan_store.get(scan_id)
    if report is None:
        raise HTTPException(
            status_code=404,
            detail=f"Scan {scan_id} not found",
        )
    return report


async def _execute_scan(report: ScanReport, request: ScanRequest) -> None:
    """Execute a scan in the background and update the report.

    Args:
        report: The scan report to update.
        request: The original scan request.
    """
    try:
        report.status = ScanStatus.RUNNING

        updated_report = await _scanner.scan(
            target_url=request.target_url,
            api_key=request.api_key,
            probes=request.probes if request.probes != ["all"] else None,
        )

        # Copy results from the updated report
        report.results = updated_report.results
        report.summary = updated_report.summary
        report.status = updated_report.status

    except Exception as e:
        logger.error("Background scan failed: %s", e)
        report.status = ScanStatus.FAILED
        report.error = str(e)