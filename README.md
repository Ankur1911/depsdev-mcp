# depsdev-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for [deps.dev](https://deps.dev) (Open Source Insights), the free Google-run service that tracks versions, licences, security advisories and dependency graphs for open-source packages. It needs no API key.

The tools are shaped around questions people ask when choosing or reviewing a dependency, rather than one tool per endpoint. Advisories are resolved to titles and severities in the same call, responses are trimmed to the fields that matter, and failures come back as readable messages.

Supported ecosystems: npm, PyPI, Cargo, Go, Maven, NuGet and RubyGems (resolved dependency graphs: npm, PyPI, Cargo and Maven).

## Setup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone <this repo> && cd depsdev-mcp
uv sync
uv run depsdev-mcp          # stdio transport
```

Add it to any MCP client that launches stdio servers:

```json
{
  "mcpServers": {
    "depsdev": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/depsdev-mcp", "depsdev-mcp"]
    }
  }
}
```

For HTTP instead of stdio: `MCP_TRANSPORT=streamable-http MCP_HOST=127.0.0.1 MCP_PORT=8000 uv run depsdev-mcp`.

## Tools

All tools are read-only.

| Tool | What it returns |
|---|---|
| `package_overview` | Default version, version and deprecation counts, most recent versions. Use it to pick a version. |
| `version_details` | Licences, publish date, deprecation, source projects, provenance flag, and the version's advisories with titles and severity (resolved in the same call). |
| `dependencies` | Resolved dependencies of a version: direct or all, with direct/indirect counts. |
| `requirements` | Declared dependency constraints in the ecosystem's own form. Works for every supported system. |
| `audit_package` | One-call review: the version's own advisories by severity, plus which of its dependencies (direct first) have known advisories. |
| `advisory` | One advisory by OSV id: title, severity, CVSS v3 score and vector, CVE aliases. |
| `project_health` | Stars, forks, open issues, licence and the OpenSSF Scorecard overall score, listing only the weak checks by default. |
| `project_packages` | Packages published from a source repository, grouped, verified links first. |
| `lookup_hash` | Which package versions a file hash (MD5, SHA1, SHA256, SHA512; hex or base64) belongs to. |

Version arguments are optional; when omitted the package's default (latest stable) version is used.

## Configuration

All optional environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `DEPSDEV_BASE_URL` | `https://api.deps.dev/v3` | API root (for a mirror or proxy) |
| `DEPSDEV_TIMEOUT` | `30` | Request timeout in seconds |
| `DEPSDEV_RETRIES` | `2` | Retries on HTTP 429, 502, 503, 504 and timeouts |
| `DEPSDEV_MAX_CHARS` | `20000` | Responses longer than this are cut with a notice |
| `MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http` |

## Limits

- `audit_package` checks at most `max_dependencies` (default 60) dependencies, direct ones first, with up to 8 requests in flight. Large trees are reported as partially checked.
- Advisory data comes from deps.dev, which mirrors OSV. A clean result means no advisory is recorded there, not that a package is safe.
- Scorecard data is only present for projects that the OpenSSF Scorecard project scans, and it can be several weeks old.
- `project_packages` reflects at most the 1,500 package versions that deps.dev returns for a project, so the package count can be a lower bound for very popular repositories.
- deps.dev does not document rate limits. The server retries politely but does not queue requests.

## Development

```bash
uv sync
uv run pytest
```

Tests mock all HTTP traffic with `respx`; no network access is needed.

## Licence

MIT. Author: Ankur Kapuriya. Not affiliated with or endorsed by Google or the deps.dev team.
