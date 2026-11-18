"""Response shaping for each tool. Pure async functions over a DepsDevClient."""

from __future__ import annotations

import asyncio
import base64
import binascii
from typing import Any

from .client import DepsDevClient, DepsDevError, enc, norm_system

GRAPH_SYSTEMS = {"NPM", "CARGO", "MAVEN", "PYPI"}
REQUIREMENT_SYSTEMS = {"NPM", "CARGO", "MAVEN", "PYPI", "GO", "NUGET", "RUBYGEMS"}
HASH_TYPES = {"MD5": 32, "SHA1": 40, "SHA256": 64, "SHA512": 128}
CONCURRENCY = 8


def severity(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "none"


def _vpath(system: str, name: str, version: str) -> str:
    return f"/systems/{system}/packages/{enc(name)}/versions/{enc(version)}"


async def resolve_version(c: DepsDevClient, system: str, name: str, version: str | None) -> str:
    """Return `version`, or the package's default (latest stable) version when omitted."""
    if version:
        return version
    pkg = await c.get(f"/systems/{system}/packages/{enc(name)}")
    versions = pkg.get("versions", [])
    for v in versions:
        if v.get("isDefault"):
            return v["versionKey"]["version"]
    live = [v for v in versions if not v.get("isDeprecated")] or versions
    if not live:
        raise DepsDevError(f"{system.lower()}/{name} has no versions in deps.dev.")
    return max(live, key=lambda v: v.get("publishedAt", ""))["versionKey"]["version"]


_advisory_cache: dict[str, dict[str, Any]] = {}


async def _advisory_summary(c: DepsDevClient, adv_id: str) -> dict[str, Any]:
    if adv_id in _advisory_cache:
        return _advisory_cache[adv_id]
    try:
        raw = await c.get(f"/advisories/{enc(adv_id)}")
    except DepsDevError as exc:
        return {"id": adv_id, "error": str(exc)}
    score = raw.get("cvss3Score")
    out = {
        "id": adv_id,
        "title": raw.get("title"),
        "severity": severity(score),
        "cvss3": score,
        "aliases": raw.get("aliases", []),
        "url": raw.get("url"),
    }
    _advisory_cache[adv_id] = out
    return out


async def resolve_advisories(c: DepsDevClient, ids: list[str]) -> list[dict[str, Any]]:
    sem = asyncio.Semaphore(CONCURRENCY)

    async def one(i: str) -> dict[str, Any]:
        async with sem:
            return await _advisory_summary(c, i)

    found = await asyncio.gather(*(one(i) for i in ids))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4, "unknown": 5}
    return sorted(found, key=lambda a: (order.get(a.get("severity", "unknown"), 5), a["id"]))


def _advisory_ids(version_doc: dict[str, Any]) -> list[str]:
    return [a["id"] for a in version_doc.get("advisoryKeys", [])]


def _summarise_version(doc: dict[str, Any]) -> dict[str, Any]:
    key = doc["versionKey"]
    links = {l["label"].lower(): l["url"] for l in doc.get("links", []) if l.get("url")}
    projects = sorted({p["projectKey"]["id"] for p in doc.get("relatedProjects", [])})
    out: dict[str, Any] = {
        "system": key["system"].lower(),
        "name": key["name"],
        "version": key["version"],
        "published": doc.get("publishedAt"),
        "default": bool(doc.get("isDefault")),
        "deprecated": bool(doc.get("isDeprecated")),
        "licenses": doc.get("licenses", []),
        "links": links,
        "projects": projects,
        "has_provenance": bool(doc.get("slsaProvenances") or doc.get("attestations")),
    }
    if doc.get("deprecatedReason"):
        out["deprecated_reason"] = doc["deprecatedReason"]
    return out


async def package_overview(c: DepsDevClient, system: str, name: str, recent: int = 10) -> dict[str, Any]:
    system = norm_system(system)
    pkg = await c.get(f"/systems/{system}/packages/{enc(name)}")
    versions = pkg.get("versions", [])
    by_date = sorted(versions, key=lambda v: v.get("publishedAt", ""), reverse=True)
    default = next((v["versionKey"]["version"] for v in versions if v.get("isDefault")), None)
    return {
        "system": system.lower(),
        "name": name,
        "default_version": default,
        "total_versions": len(versions),
        "deprecated_versions": sum(1 for v in versions if v.get("isDeprecated")),
        "latest_published": by_date[0]["versionKey"]["version"] if by_date else None,
        "recent_versions": [
            {
                "version": v["versionKey"]["version"],
                "published": v.get("publishedAt"),
                **({"deprecated": True} if v.get("isDeprecated") else {}),
            }
            for v in by_date[: max(recent, 0)]
        ],
    }


async def version_details(c: DepsDevClient, system: str, name: str, version: str | None = None) -> dict[str, Any]:
    system = norm_system(system)
    version = await resolve_version(c, system, name, version)
    doc = await c.get(_vpath(system, name, version))
    out = _summarise_version(doc)
    out["advisories"] = await resolve_advisories(c, _advisory_ids(doc))
    return out


def _graph(doc: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = doc.get("nodes", [])
    out = []
    for n in nodes:
        rel = n.get("relation", "").lower()
        if rel == "self":
            continue
        k = n["versionKey"]
        item = {"name": k["name"], "version": k["version"], "relation": rel}
        if n.get("bundled"):
            item["bundled"] = True
        if n.get("errors"):
            item["errors"] = n["errors"]
        out.append(item)
    return out


async def dependencies(
    c: DepsDevClient, system: str, name: str, version: str | None = None, scope: str = "direct", limit: int = 100
) -> dict[str, Any]:
    system = norm_system(system)
    if system not in GRAPH_SYSTEMS:
        raise DepsDevError(
            f"deps.dev resolves full dependency graphs only for {', '.join(sorted(GRAPH_SYSTEMS)).lower()}. "
            f"For {system.lower()} use the requirements tool for declared constraints."
        )
    if scope not in ("direct", "all"):
        raise DepsDevError("scope must be 'direct' or 'all'.")
    version = await resolve_version(c, system, name, version)
    doc = await c.get(_vpath(system, name, version) + ":dependencies")
    nodes = _graph(doc)
    direct = [n for n in nodes if n["relation"] == "direct"]
    shown = direct if scope == "direct" else nodes
    out: dict[str, Any] = {
        "package": f"{system.lower()}/{name}@{version}",
        "direct_count": len(direct),
        "indirect_count": len(nodes) - len(direct),
        "dependencies": shown[: max(limit, 0)],
    }
    if len(shown) > limit:
        out["note"] = f"Showing {limit} of {len(shown)}; raise limit to see more."
    if doc.get("error"):
        out["resolution_error"] = doc["error"]
    return out


async def requirements(c: DepsDevClient, system: str, name: str, version: str | None = None) -> dict[str, Any]:
    system = norm_system(system)
    version = await resolve_version(c, system, name, version)
    doc = await c.get(_vpath(system, name, version) + ":requirements")
    return {"package": f"{system.lower()}/{name}@{version}", "requirements": doc}


async def advisory(c: DepsDevClient, advisory_id: str) -> dict[str, Any]:
    raw = await c.get(f"/advisories/{enc(advisory_id)}")
    score = raw.get("cvss3Score")
    return {
        "id": advisory_id,
        "title": raw.get("title"),
        "severity": severity(score),
        "cvss3": score,
        "cvss3_vector": raw.get("cvss3Vector"),
        "aliases": raw.get("aliases", []),
        "url": raw.get("url"),
    }


async def project_health(c: DepsDevClient, project_id: str, all_checks: bool = False) -> dict[str, Any]:
    pid = project_id.strip().removeprefix("https://").removeprefix("http://").rstrip("/").removesuffix(".git")
    raw = await c.get(f"/projects/{enc(pid)}")
    out: dict[str, Any] = {
        "project": pid,
        "description": raw.get("description"),
        "homepage": raw.get("homepage"),
        "license": raw.get("license"),
        "stars": raw.get("starsCount"),
        "forks": raw.get("forksCount"),
        "open_issues": raw.get("openIssuesCount"),
    }
    sc = raw.get("scorecard")
    if not sc:
        out["scorecard"] = None
        return out
    checks = [ch for ch in sc.get("checks", []) if ch.get("score", -1) >= 0]
    checks.sort(key=lambda ch: (ch["score"], ch["name"]))
    picked = checks if all_checks else [ch for ch in checks if ch["score"] < 10]
    out["scorecard"] = {
        "overall": sc.get("overallScore"),
        "date": (sc.get("date") or "")[:10],
        "checks_scored": len(checks),
        ("checks" if all_checks else "weak_checks"): [
            {"name": ch["name"], "score": ch["score"], "reason": (ch.get("reason") or "")[:160]} for ch in picked
        ],
    }
    return out


async def project_packages(c: DepsDevClient, project_id: str, limit: int = 25) -> dict[str, Any]:
    pid = project_id.strip().removeprefix("https://").rstrip("/").removesuffix(".git")
    raw = await c.get(f"/projects/{enc(pid)}:packageversions")
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for v in raw.get("versions", []):
        k = v["versionKey"]
        g = groups.setdefault(
            (k["system"], k["name"]),
            {"system": k["system"].lower(), "name": k["name"], "versions": 0, "relation": v.get("relationType"), "verified": False},
        )
        g["versions"] += 1
        if v.get("relationProvenance") in ("SLSA_ATTESTATION", "PYPI_PUBLISH_ATTESTATION", "NPM_PUBLISH_ATTESTATION"):
            g["verified"] = True
    ranked = sorted(groups.values(), key=lambda g: (not g["verified"], g["relation"] != "SOURCE_REPO", -g["versions"], g["name"]))
    out: dict[str, Any] = {"project": pid, "package_count": len(ranked), "packages": ranked[: max(limit, 0)]}
    if len(ranked) > limit:
        out["note"] = f"Showing {limit} of {len(ranked)} packages (verified source-repo links first); raise limit to see more."
    return out


def to_base64_hash(hash_type: str, value: str) -> tuple[str, str]:
    ht = hash_type.strip().upper().replace("-", "")
    if ht not in HASH_TYPES:
        raise DepsDevError(f"hash_type must be one of {', '.join(HASH_TYPES)}.")
    v = value.strip()
    if len(v) == HASH_TYPES[ht]:
        try:
            return ht, base64.b64encode(bytes.fromhex(v)).decode()
        except ValueError:
            pass
    try:
        base64.b64decode(v, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DepsDevError("hash_value must be a hex digest or a base64 string.") from exc
    return ht, v


async def lookup_hash(c: DepsDevClient, hash_type: str, hash_value: str, limit: int = 10) -> dict[str, Any]:
    ht, b64 = to_base64_hash(hash_type, hash_value)
    raw = await c.get("/query", params={"hash.type": ht, "hash.value": b64})
    results = raw.get("results", [])
    items = []
    for r in results[: max(limit, 0)]:
        v = r.get("version", {})
        k = v.get("versionKey", {})
        items.append(
            {
                "system": k.get("system", "").lower(),
                "name": k.get("name"),
                "version": k.get("version"),
                "published": v.get("publishedAt"),
                "licenses": v.get("licenses", []),
                "advisory_count": len(v.get("advisoryKeys", [])),
            }
        )
    out: dict[str, Any] = {"match_count": len(results), "matches": items}
    if len(results) > limit:
        out["note"] = f"Showing {limit} of {len(results)} matches."
    return out


async def audit_package(
    c: DepsDevClient, system: str, name: str, version: str | None = None, max_dependencies: int = 60
) -> dict[str, Any]:
    """One-call review: version facts, advisories, dependency count and vulnerable dependencies."""
    system = norm_system(system)
    version = await resolve_version(c, system, name, version)
    doc = await c.get(_vpath(system, name, version))
    out = _summarise_version(doc)
    own = await resolve_advisories(c, _advisory_ids(doc))
    out["advisories"] = own

    dep_report: dict[str, Any]
    if system not in GRAPH_SYSTEMS:
        dep_report = {"checked": False, "reason": f"deps.dev has no resolved dependency graph for {system.lower()}."}
    else:
        try:
            graph = _graph(await c.get(_vpath(system, name, version) + ":dependencies"))
        except DepsDevError as exc:
            graph = None
            dep_report = {"checked": False, "reason": str(exc)}
        if graph is not None:
            cap = max(max_dependencies, 0)
            # Direct dependencies first, so the cap trims the least relevant ones.
            graph.sort(key=lambda n: n["relation"] != "direct")
            subset = graph[:cap]
            sem = asyncio.Semaphore(CONCURRENCY)

            async def check(n: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
                async with sem:
                    try:
                        d = await c.get(_vpath(system, n["name"], n["version"]))
                    except DepsDevError:
                        return n, ["?lookup-failed"]
                    return n, _advisory_ids(d)

            checked = await asyncio.gather(*(check(n) for n in subset))
            failed = sum(1 for _, ids in checked if ids == ["?lookup-failed"])
            vulnerable = [(n, ids) for n, ids in checked if ids and ids != ["?lookup-failed"]]
            all_ids = sorted({i for _, ids in vulnerable for i in ids})
            details = {a["id"]: a for a in await resolve_advisories(c, all_ids)}
            findings = []
            for n, ids in vulnerable:
                advs = [details[i] for i in ids]
                worst = min(advs, key=lambda a: ["critical", "high", "medium", "low", "none", "unknown"].index(a["severity"]))
                findings.append(
                    {
                        "dependency": f"{n['name']}@{n['version']}",
                        "relation": n["relation"],
                        "worst_severity": worst["severity"],
                        "advisories": [{"id": a["id"], "severity": a["severity"], "title": a.get("title")} for a in advs],
                    }
                )
            rank = ["critical", "high", "medium", "low", "none", "unknown"]
            findings.sort(key=lambda f: (rank.index(f["worst_severity"]), f["dependency"]))
            dep_report = {
                "checked": True,
                "total_dependencies": len(graph),
                "checked_count": len(subset),
                "lookup_failures": failed,
                "vulnerable": findings,
            }
            if len(graph) > cap:
                dep_report["note"] = f"Only the first {cap} of {len(graph)} dependencies were checked (direct ones first); raise max_dependencies."
    out["dependencies"] = dep_report
    counts: dict[str, int] = {}
    for a in own:
        counts[a["severity"]] = counts.get(a["severity"], 0) + 1
    out["summary"] = {
        "own_advisories": len(own),
        "own_by_severity": counts,
        "vulnerable_dependencies": len(dep_report.get("vulnerable", [])),
        "deprecated": out["deprecated"],
    }
    return out
