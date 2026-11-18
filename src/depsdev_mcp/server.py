"""MCP server exposing the deps.dev API as a small set of task-shaped tools."""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from . import tools
from .client import DepsDevClient, DepsDevError

System = Annotated[
    Literal["npm", "pypi", "cargo", "go", "maven", "nuget", "rubygems"],
    Field(description="Package ecosystem. Maven names are 'group:artifact'; Go names are module paths such as github.com/gin-gonic/gin."),
]
Name = Annotated[str, Field(description="Exact package name as published in its registry.")]
Version = Annotated[str | None, Field(description="Version string. Omit to use the package's default (latest stable) version.")]
ProjectId = Annotated[str, Field(description="Source project id such as 'github.com/expressjs/express' (GitHub, GitLab or Bitbucket).")]

MAX_CHARS = 20000
READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=True, idempotent_hint=True)

client = DepsDevClient()
mcp = MCPServer(
    "depsdev",
    instructions=(
        "Look up open-source package facts from deps.dev (Open Source Insights): versions, licences, "
        "security advisories, dependency graphs and source-project health. Start with audit_package for "
        "a quick review of one package, or package_overview to find which version to inspect. "
        "Data is read-only and needs no credentials."
    ),
)


def render(data: Any) -> str:
    text = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    limit = int(os.environ.get("DEPSDEV_MAX_CHARS", MAX_CHARS))
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[truncated: response was {len(text)} characters; use a smaller limit or a narrower tool]"


async def run(coro: Any) -> str:
    try:
        return render(await coro)
    except DepsDevError as exc:
        raise ToolError(str(exc)) from exc


@mcp.tool(
    name="package_overview",
    description=(
        "Summarise a package: default version, number of versions, how many are deprecated, and the most "
        "recently published versions. Use this first to pick a version for the other tools."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def package_overview(
    system: System, name: Name, recent: Annotated[int, Field(description="How many recent versions to list.", ge=0, le=100)] = 10
) -> str:
    return await run(tools.package_overview(client, system, name, recent))


@mcp.tool(
    name="version_details",
    description=(
        "Facts about one package version: licences, publish date, deprecation, source projects, provenance "
        "flag, and its known security advisories with severity (already resolved, no extra calls needed)."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def version_details(system: System, name: Name, version: Version = None) -> str:
    return await run(tools.version_details(client, system, name, version))


@mcp.tool(
    name="dependencies",
    description=(
        "List the resolved dependencies of a version (npm, cargo, maven, pypi). Returns direct and indirect "
        "counts; scope 'direct' lists only direct dependencies, 'all' includes the transitive ones."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def dependencies(
    system: System,
    name: Name,
    version: Version = None,
    scope: Annotated[Literal["direct", "all"], Field(description="Which dependencies to list.")] = "direct",
    limit: Annotated[int, Field(description="Maximum dependencies to return.", ge=1, le=500)] = 100,
) -> str:
    return await run(tools.dependencies(client, system, name, version, scope, limit))


@mcp.tool(
    name="requirements",
    description=(
        "Declared dependency constraints of a version, in the ecosystem's own form (for example npm "
        "dependencies and devDependencies with version ranges). Works for all systems, including go, nuget and rubygems."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def requirements(system: System, name: Name, version: Version = None) -> str:
    return await run(tools.requirements(client, system, name, version))


@mcp.tool(
    name="audit_package",
    description=(
        "One-call security and hygiene review of a package version: licences, deprecation, its own advisories "
        "by severity, and which of its dependencies (direct first) have known advisories. Replaces many separate lookups."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def audit_package(
    system: System,
    name: Name,
    version: Version = None,
    max_dependencies: Annotated[int, Field(description="Cap on dependencies checked for advisories.", ge=0, le=300)] = 60,
) -> str:
    return await run(tools.audit_package(client, system, name, version, max_dependencies))


@mcp.tool(
    name="advisory",
    description="Details of one security advisory by its OSV id (for example GHSA-xxxx-xxxx-xxxx): title, severity, CVSS v3, aliases such as CVE ids.",
    annotations=READ_ONLY,
    structured_output=False,
)
async def advisory(advisory_id: Annotated[str, Field(description="OSV advisory id, e.g. GHSA-qw6h-vgh9-j6wx.")]) -> str:
    return await run(tools.advisory(client, advisory_id))


@mcp.tool(
    name="project_health",
    description=(
        "Health of a source repository: stars, forks, open issues, licence and the OpenSSF Scorecard overall "
        "score. By default lists only the checks that scored below 10, weakest first."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def project_health(
    project_id: ProjectId, all_checks: Annotated[bool, Field(description="Include every scored check, not just the weak ones.")] = False
) -> str:
    return await run(tools.project_health(client, project_id, all_checks))


@mcp.tool(
    name="project_packages",
    description="Packages published from a source project, grouped by package with version counts. Verified source-repo links are listed first.",
    annotations=READ_ONLY,
    structured_output=False,
)
async def project_packages(
    project_id: ProjectId, limit: Annotated[int, Field(description="Maximum packages to return.", ge=1, le=200)] = 25
) -> str:
    return await run(tools.project_packages(client, project_id, limit))


@mcp.tool(
    name="lookup_hash",
    description="Identify which package versions a file hash belongs to (for example the SHA-256 of a downloaded archive). Accepts hex or base64.",
    annotations=READ_ONLY,
    structured_output=False,
)
async def lookup_hash(
    hash_type: Annotated[Literal["MD5", "SHA1", "SHA256", "SHA512"], Field(description="Hash algorithm.")],
    hash_value: Annotated[str, Field(description="Digest as a hex or base64 string.")],
    limit: Annotated[int, Field(description="Maximum matches to return.", ge=1, le=100)] = 10,
) -> str:
    return await run(tools.lookup_hash(client, hash_type, hash_value, limit))


def main() -> None:
    logging.basicConfig(stream=sys.stderr, level=os.environ.get("LOG_LEVEL", "WARNING").upper())
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "stdio":
        mcp.run("stdio")
    else:
        mcp.run(transport, host=os.environ.get("MCP_HOST", "127.0.0.1"), port=int(os.environ.get("MCP_PORT", "8000")))


if __name__ == "__main__":
    main()
