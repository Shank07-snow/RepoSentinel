from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

APP_VERSION = "0.1.0"
PYPI_URL = "https://pypi.org/pypi/{name}/json"
OSV_URL = "https://api.osv.dev/v1/query"

app = FastAPI(
    title="RepoSentinel API",
    description="Software supply-chain risk intelligence for the Python ecosystem.",
    version=APP_VERSION,
)

PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")


class PackageSummary(BaseModel):
    name: str
    latest_version: str | None = None
    project_url: str | None = None
    summary: str | None = None
    license: str | None = None
    published_at: str | None = None


class AdvisorySummary(BaseModel):
    id: str
    summary: str | None = None
    modified: str | None = None
    published: str | None = None
    aliases: list[str] = Field(default_factory=list)


async def fetch_json(url: str, *, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    timeout = httpx.Timeout(12.0, connect=5.0)
    limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
    async with httpx.AsyncClient(timeout=timeout, limits=limits, follow_redirects=False) as client:
        response = await (client.post(url, json=payload) if payload is not None else client.get(url))
        if response.status_code == 404:
            raise HTTPException(status_code=404, detail="Package or resource was not found.")
        if response.status_code >= 400:
            raise HTTPException(status_code=502, detail="Upstream data provider returned an error.")
        if len(response.content) > 2_000_000:
            raise HTTPException(status_code=502, detail="Upstream response exceeded the size limit.")
        try:
            return response.json()
        except ValueError as exc:
            raise HTTPException(status_code=502, detail="Upstream provider returned invalid JSON.") from exc


def validate_package_name(name: str) -> str:
    normalized = name.strip()
    if not PACKAGE_RE.fullmatch(normalized):
        raise HTTPException(status_code=422, detail="Invalid PyPI package name.")
    return normalized


@app.get("/", tags=["meta"])
async def root() -> dict[str, str]:
    return {"name": "RepoSentinel API", "version": APP_VERSION, "docs": "/docs"}


@app.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/packages/{package_name}", response_model=PackageSummary, tags=["packages"])
async def inspect_package(package_name: str) -> PackageSummary:
    name = validate_package_name(package_name)
    data = await fetch_json(PYPI_URL.format(name=name))
    info = data.get("info", {})
    project_urls = info.get("project_urls") or {}
    return PackageSummary(
        name=info.get("name") or name,
        latest_version=info.get("version"),
        project_url=info.get("project_url") or project_urls.get("Homepage"),
        summary=info.get("summary"),
        license=info.get("license"),
    )


@app.get("/packages/{package_name}/advisories", response_model=list[AdvisorySummary], tags=["security"])
async def package_advisories(
    package_name: str,
    version: str | None = Query(default=None, max_length=100),
) -> list[AdvisorySummary]:
    name = validate_package_name(package_name)
    query: dict[str, Any] = {"package": {"name": name, "ecosystem": "PyPI"}}
    if version:
        query["version"] = version
    data = await fetch_json(OSV_URL, payload=query)
    results = []
    for item in data.get("vulns", []):
        results.append(AdvisorySummary(
            id=item.get("id", "UNKNOWN"),
            summary=item.get("summary"),
            modified=item.get("modified"),
            published=item.get("published"),
            aliases=item.get("aliases") or [],
        ))
    return results
