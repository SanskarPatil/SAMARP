"""Read-only Plane B HTTP routes for PS26145 monitoring and export.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 17, 18, 19, design.md section 19.

Plane B is strictly read-only over HTTP: GET only. No POST, PUT, PATCH, or DELETE.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

router = APIRouter()


@router.get("/health", summary="System Health and Read-Only Verification")
def get_health(request: Request) -> dict[str, Any]:
    """Return component health, uptime, incident counts, and read-only status."""
    app_state = request.app.state.service_state
    return app_state.get_health()


@router.get("/capabilities", summary="Capability / Visibility Declaration")
def get_capabilities(request: Request) -> dict[str, Any]:
    """Return current capability and visibility declarations across input sources."""
    app_state = request.app.state.service_state
    return app_state.get_capabilities()


@router.get("/incidents", summary="Query Latest Incidents")
def list_incidents(
    request: Request,
    status: str | None = Query(default=None, description="Filter by lifecycle status: NEW, ACTIVE, UPDATED, RESOLVED"),
    ps_class: str | None = Query(default=None, description="Filter by PS threat class string"),
    severity: str | None = Query(default=None, description="Filter by severity: INFO, LOW, MEDIUM, HIGH, CRITICAL"),
    limit: int = Query(default=100, ge=1, le=1000, description="Max items to return"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
) -> list[dict[str, Any]]:
    """Query current incidents matching optional filters, ordered by last_observed DESC."""
    app_state = request.app.state.service_state
    return app_state.store.list_incidents(
        status=status,
        ps_class=ps_class,
        severity=severity,
        limit=limit,
        offset=offset,
    )


@router.get("/incidents/{incident_id}", summary="Get Incident by ID")
def get_incident(request: Request, incident_id: str) -> dict[str, Any]:
    """Retrieve full incident payload for a specific 16-hex incident ID."""
    app_state = request.app.state.service_state
    incident = app_state.store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return incident


@router.get("/incidents/{incident_id}/history", summary="Get Incident Update History")
def get_incident_history(request: Request, incident_id: str) -> list[dict[str, Any]]:
    """Retrieve chronological update sequence for a specific incident."""
    app_state = request.app.state.service_state
    incident = app_state.store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return app_state.store.get_incident_history(incident_id)


@router.get("/export/json", summary="Export Complete Signed Hash Chain (Canonical JSON)")
def export_json(request: Request) -> JSONResponse:
    """Export complete, chronological, tamper-evident hash chain sequence as canonical JSON."""
    app_state = request.app.state.service_state
    entries = app_state.store.get_all_signed_entries()
    return JSONResponse(
        content=entries,
        headers={"Content-Disposition": 'attachment; filename="incidents_hash_chain.json"'},
    )


@router.get("/export/csv", summary="Export Incidents (Spreadsheet Flattened CSV)")
def export_csv(request: Request) -> Response:
    """Export incidents in flattened CSV format per V6.3 section 18 rules."""
    app_state = request.app.state.service_state
    csv_text = app_state.store.export_csv()
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="incidents.csv"'},
    )
