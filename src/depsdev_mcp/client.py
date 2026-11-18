"""Small async client for the deps.dev v3 REST API (public, no authentication)."""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any
from urllib.parse import quote

import httpx

log = logging.getLogger("depsdev_mcp")

DEFAULT_BASE_URL = "https://api.deps.dev/v3"
SYSTEMS = ("NPM", "PYPI", "CARGO", "GO", "MAVEN", "NUGET", "RUBYGEMS")
RETRY_STATUSES = {429, 502, 503, 504}


class DepsDevError(Exception):
    """An API or network failure with a message that is safe to show a model."""


def enc(value: str) -> str:
    """Percent-encode one path segment ('/' becomes %2F, as the API requires)."""
    return quote(str(value), safe="")


def norm_system(system: str) -> str:
    s = system.strip().upper()
    if s not in SYSTEMS:
        raise DepsDevError(f"Unknown package system '{system}'. Use one of: {', '.join(SYSTEMS)}.")
    return s


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


class DepsDevClient:
    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    @property
    def base_url(self) -> str:
        return os.environ.get("DEPSDEV_BASE_URL", DEFAULT_BASE_URL).rstrip("/")

    def _http(self) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        if self._client is None or self._client.is_closed or self._loop is not loop:
            self._loop = loop
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(_float_env("DEPSDEV_TIMEOUT", 30.0), connect=10.0),
                headers={"Accept": "application/json", "User-Agent": "depsdev-mcp/0.1"},
                follow_redirects=True,
            )
        return self._client

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET `path` (already encoded), retrying briefly on rate limits and 5xx."""
        url = self.base_url + path
        retries = int(_float_env("DEPSDEV_RETRIES", 2))
        delay = _float_env("DEPSDEV_RETRY_DELAY", 1.0)
        for attempt in range(retries + 1):
            try:
                resp = await self._http().get(url, params=params)
            except httpx.TimeoutException as exc:
                if attempt < retries:
                    await asyncio.sleep(delay * 2**attempt)
                    continue
                raise DepsDevError(f"GET {path} timed out ({type(exc).__name__}). deps.dev may be slow; retry later.") from exc
            except httpx.HTTPError as exc:
                raise DepsDevError(f"GET {path} failed: {type(exc).__name__}: {exc}") from exc
            if resp.status_code in RETRY_STATUSES and attempt < retries:
                wait = delay * 2**attempt
                retry_after = resp.headers.get("retry-after")
                if retry_after and retry_after.isdigit():
                    wait = min(float(retry_after), 10.0)
                await asyncio.sleep(wait)
                continue
            break
        if resp.status_code == 404:
            raise DepsDevError(f"Not found: {path}. Check the system, package name, version or project id.")
        if resp.status_code == 429:
            raise DepsDevError("Rate limited by deps.dev. Wait a moment and retry with fewer parallel lookups.")
        if resp.status_code >= 400:
            detail = resp.text[:300].strip()
            raise DepsDevError(f"deps.dev returned HTTP {resp.status_code} for {path}. {detail}")
        try:
            return resp.json()
        except ValueError as exc:
            raise DepsDevError(f"deps.dev returned a non-JSON response for {path}.") from exc
