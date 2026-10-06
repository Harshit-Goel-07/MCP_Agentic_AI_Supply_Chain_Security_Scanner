"""FastAPI application (server mode).

Exposes synchronous scanning of inline server definitions plus the rule catalog and SARIF export.
Requires the ``api`` extra: ``pip install -e '.[api]'``.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from mcpscan.config import Settings
from mcpscan.models import ScanResult, ServerModel
from mcpscan.report import to_sarif
from mcpscan.rules.engine import load_catalog
from mcpscan.scanner import Scanner
from mcpscan.version import __version__

app = FastAPI(title="MCPScan API", version=__version__)


class ScanRequest(BaseModel):
    servers: list[ServerModel]
    enable_semantic: bool = False


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/api/v1/rules")
def rules() -> dict[str, Any]:
    catalog = load_catalog()
    return catalog.model_dump(mode="json")


@app.post("/api/v1/scans", response_model=ScanResult)
def create_scan(request: ScanRequest) -> ScanResult:
    scanner = Scanner(settings=Settings(enable_semantic=request.enable_semantic))
    return scanner.scan_servers(request.servers)


@app.post("/api/v1/scans/sarif")
def create_scan_sarif(request: ScanRequest) -> dict[str, Any]:
    scanner = Scanner(settings=Settings(enable_semantic=request.enable_semantic))
    result = scanner.scan_servers(request.servers)
    return to_sarif(result)
