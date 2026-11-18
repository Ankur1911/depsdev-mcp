import json

import httpx
import pytest
import respx
from mcp import Client

from depsdev_mcp import server, tools

BASE = "https://api.deps.dev/v3"


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.setenv("DEPSDEV_RETRY_DELAY", "0")
    monkeypatch.delenv("DEPSDEV_BASE_URL", raising=False)
    monkeypatch.delenv("DEPSDEV_MAX_CHARS", raising=False)
    tools._advisory_cache.clear()


async def call(tool, args=None):
    async with Client(server.mcp) as c:
        return await c.call_tool(tool, args or {})


def data(result):
    return json.loads("".join(x.text for x in result.content))


def text(result):
    return "".join(x.text for x in result.content)


def vk(name, version, system="NPM"):
    return {"system": system, "name": name, "version": version}


PKG = {
    "packageKey": {"system": "NPM", "name": "left"},
    "versions": [
        {"versionKey": vk("left", "1.0.0"), "publishedAt": "2020-01-01T00:00:00Z", "isDefault": False, "isDeprecated": True},
        {"versionKey": vk("left", "2.0.0"), "publishedAt": "2022-01-01T00:00:00Z", "isDefault": True, "isDeprecated": False},
        {"versionKey": vk("left", "3.0.0-beta"), "publishedAt": "2023-01-01T00:00:00Z", "isDefault": False, "isDeprecated": False},
    ],
}


def version_doc(name, version, advisories=(), **extra):
    return {
        "versionKey": vk(name, version),
        "publishedAt": "2022-01-01T00:00:00Z",
        "isDefault": False,
        "isDeprecated": False,
        "licenses": ["MIT"],
        "advisoryKeys": [{"id": a} for a in advisories],
        "links": [{"label": "SOURCE_REPO", "url": "https://github.com/x/left"}],
        "relatedProjects": [
            {"projectKey": {"id": "github.com/x/left"}, "relationType": "SOURCE_REPO"},
            {"projectKey": {"id": "github.com/x/left"}, "relationType": "ISSUE_TRACKER"},
        ],
        **extra,
    }


def advisory_doc(adv_id, score, title="Bad thing"):
    return {"advisoryKey": {"id": adv_id}, "url": f"https://osv.dev/vulnerability/{adv_id}", "title": title, "aliases": ["CVE-1"], "cvss3Score": score, "cvss3Vector": "CVSS:3.1/x"}


@respx.mock
async def test_package_overview_orders_by_date_and_counts():
    respx.get(f"{BASE}/systems/NPM/packages/left").mock(return_value=httpx.Response(200, json=PKG))
    out = data(await call("package_overview", {"system": "npm", "name": "left", "recent": 2}))
    assert out["default_version"] == "2.0.0"
    assert out["latest_published"] == "3.0.0-beta"
    assert out["total_versions"] == 3 and out["deprecated_versions"] == 1
    assert [v["version"] for v in out["recent_versions"]] == ["3.0.0-beta", "2.0.0"]


@respx.mock
async def test_version_details_resolves_default_and_advisories_sorted():
    respx.get(f"{BASE}/systems/NPM/packages/left").mock(return_value=httpx.Response(200, json=PKG))
    respx.get(f"{BASE}/systems/NPM/packages/left/versions/2.0.0").mock(
        return_value=httpx.Response(200, json=version_doc("left", "2.0.0", ["A-1", "A-2"]))
    )
    respx.get(f"{BASE}/advisories/A-1").mock(return_value=httpx.Response(200, json=advisory_doc("A-1", 5.0)))
    respx.get(f"{BASE}/advisories/A-2").mock(return_value=httpx.Response(200, json=advisory_doc("A-2", 9.8)))
    out = data(await call("version_details", {"system": "npm", "name": "left"}))
    assert out["version"] == "2.0.0"
    assert out["projects"] == ["github.com/x/left"]  # de-duplicated
    assert [a["id"] for a in out["advisories"]] == ["A-2", "A-1"]  # critical first
    assert out["advisories"][0]["severity"] == "critical"
    assert out["links"] == {"source_repo": "https://github.com/x/left"}


@respx.mock
async def test_path_segments_are_encoded_for_go_and_scoped_names():
    route = respx.get(f"{BASE}/systems/GO/packages/github.com%2Fgin-gonic%2Fgin/versions/v1.9.1").mock(
        return_value=httpx.Response(200, json=version_doc("github.com/gin-gonic/gin", "v1.9.1"))
    )
    out = data(await call("version_details", {"system": "go", "name": "github.com/gin-gonic/gin", "version": "v1.9.1"}))
    assert route.called and out["version"] == "v1.9.1"


@respx.mock
async def test_dependencies_direct_vs_all_and_limit():
    graph = {
        "nodes": [
            {"versionKey": vk("left", "2.0.0"), "relation": "SELF"},
            {"versionKey": vk("a", "1.0.0"), "relation": "DIRECT"},
            {"versionKey": vk("b", "1.0.0"), "relation": "DIRECT"},
            {"versionKey": vk("c", "1.0.0"), "relation": "INDIRECT", "bundled": True},
        ],
        "edges": [],
    }
    respx.get(f"{BASE}/systems/NPM/packages/left/versions/2.0.0:dependencies").mock(return_value=httpx.Response(200, json=graph))
    out = data(await call("dependencies", {"system": "npm", "name": "left", "version": "2.0.0"}))
    assert (out["direct_count"], out["indirect_count"]) == (2, 1)
    assert [d["name"] for d in out["dependencies"]] == ["a", "b"]
    out = data(await call("dependencies", {"system": "npm", "name": "left", "version": "2.0.0", "scope": "all", "limit": 3}))
    assert len(out["dependencies"]) == 3 and out["dependencies"][2]["bundled"] is True
    out = data(await call("dependencies", {"system": "npm", "name": "left", "version": "2.0.0", "scope": "all", "limit": 2}))
    assert "Showing 2 of 3" in out["note"]


async def test_dependencies_unsupported_system_points_to_requirements():
    result = await call("dependencies", {"system": "go", "name": "x/y", "version": "v1"})
    assert result.is_error and "requirements" in text(result)


@respx.mock
async def test_requirements_passthrough():
    body = {"npm": {"dependencies": {"dependencies": [{"name": "a", "requirement": "^1"}]}}}
    respx.get(f"{BASE}/systems/NPM/packages/left/versions/2.0.0:requirements").mock(return_value=httpx.Response(200, json=body))
    out = data(await call("requirements", {"system": "npm", "name": "left", "version": "2.0.0"}))
    assert out["requirements"] == body and out["package"] == "npm/left@2.0.0"


@respx.mock
async def test_audit_package_reports_vulnerable_dependencies_worst_first():
    respx.get(f"{BASE}/systems/NPM/packages/left/versions/2.0.0").mock(return_value=httpx.Response(200, json=version_doc("left", "2.0.0", ["A-1"])))
    graph = {
        "nodes": [
            {"versionKey": vk("left", "2.0.0"), "relation": "SELF"},
            {"versionKey": vk("indirect", "1.0.0"), "relation": "INDIRECT"},
            {"versionKey": vk("clean", "1.0.0"), "relation": "DIRECT"},
            {"versionKey": vk("bad", "1.0.0"), "relation": "DIRECT"},
            {"versionKey": vk("gone", "1.0.0"), "relation": "DIRECT"},
        ]
    }
    respx.get(f"{BASE}/systems/NPM/packages/left/versions/2.0.0:dependencies").mock(return_value=httpx.Response(200, json=graph))
    respx.get(f"{BASE}/systems/NPM/packages/clean/versions/1.0.0").mock(return_value=httpx.Response(200, json=version_doc("clean", "1.0.0")))
    respx.get(f"{BASE}/systems/NPM/packages/bad/versions/1.0.0").mock(return_value=httpx.Response(200, json=version_doc("bad", "1.0.0", ["A-2", "A-3"])))
    respx.get(f"{BASE}/systems/NPM/packages/indirect/versions/1.0.0").mock(return_value=httpx.Response(200, json=version_doc("indirect", "1.0.0", ["A-3"])))
    respx.get(f"{BASE}/systems/NPM/packages/gone/versions/1.0.0").mock(return_value=httpx.Response(404))
    respx.get(f"{BASE}/advisories/A-1").mock(return_value=httpx.Response(200, json=advisory_doc("A-1", 3.0)))
    respx.get(f"{BASE}/advisories/A-2").mock(return_value=httpx.Response(200, json=advisory_doc("A-2", 7.5)))
    respx.get(f"{BASE}/advisories/A-3").mock(return_value=httpx.Response(200, json=advisory_doc("A-3", 9.1)))
    out = data(await call("audit_package", {"system": "npm", "name": "left", "version": "2.0.0"}))
    deps = out["dependencies"]
    assert deps["checked"] and deps["total_dependencies"] == 4 and deps["lookup_failures"] == 1
    assert [f["dependency"] for f in deps["vulnerable"]] == ["bad@1.0.0", "indirect@1.0.0"]
    assert deps["vulnerable"][0]["worst_severity"] == "critical"
    assert out["summary"] == {"own_advisories": 1, "own_by_severity": {"low": 1}, "vulnerable_dependencies": 2, "deprecated": False}


@respx.mock
async def test_audit_package_cap_checks_direct_dependencies_first():
    respx.get(f"{BASE}/systems/NPM/packages/left/versions/2.0.0").mock(return_value=httpx.Response(200, json=version_doc("left", "2.0.0")))
    graph = {"nodes": [{"versionKey": vk("left", "2.0.0"), "relation": "SELF"}, {"versionKey": vk("ind", "1.0.0"), "relation": "INDIRECT"}, {"versionKey": vk("dir", "1.0.0"), "relation": "DIRECT"}]}
    respx.get(f"{BASE}/systems/NPM/packages/left/versions/2.0.0:dependencies").mock(return_value=httpx.Response(200, json=graph))
    direct = respx.get(f"{BASE}/systems/NPM/packages/dir/versions/1.0.0").mock(return_value=httpx.Response(200, json=version_doc("dir", "1.0.0")))
    indirect = respx.get(f"{BASE}/systems/NPM/packages/ind/versions/1.0.0").mock(return_value=httpx.Response(200, json=version_doc("ind", "1.0.0")))
    out = data(await call("audit_package", {"system": "npm", "name": "left", "version": "2.0.0", "max_dependencies": 1}))
    assert direct.called and not indirect.called
    assert "Only the first 1 of 2" in out["dependencies"]["note"]


@respx.mock
async def test_audit_package_for_go_skips_graph():
    respx.get(f"{BASE}/systems/GO/packages/m%2Fx/versions/v1.0.0").mock(return_value=httpx.Response(200, json=version_doc("m/x", "v1.0.0")))
    out = data(await call("audit_package", {"system": "go", "name": "m/x", "version": "v1.0.0"}))
    assert out["dependencies"]["checked"] is False


@respx.mock
async def test_project_health_shows_weak_checks_only_and_accepts_url():
    body = {
        "projectKey": {"id": "github.com/x/left"},
        "starsCount": 10, "forksCount": 2, "openIssuesCount": 3, "license": "MIT", "description": "d",
        "scorecard": {
            "date": "2026-08-24T00:00:00Z", "overallScore": 6.5,
            "checks": [
                {"name": "Maintained", "score": 10, "reason": "ok"},
                {"name": "Fuzzing", "score": 0, "reason": "no fuzzer"},
                {"name": "Packaging", "score": -1, "reason": "n/a"},
                {"name": "Pinned", "score": 4, "reason": "some pinned"},
            ],
        },
    }
    route = respx.get(f"{BASE}/projects/github.com%2Fx%2Fleft").mock(return_value=httpx.Response(200, json=body))
    out = data(await call("project_health", {"project_id": "https://github.com/x/left.git"}))
    assert route.called
    assert out["scorecard"]["overall"] == 6.5 and out["scorecard"]["checks_scored"] == 3
    assert [c["name"] for c in out["scorecard"]["weak_checks"]] == ["Fuzzing", "Pinned"]
    out = data(await call("project_health", {"project_id": "github.com/x/left", "all_checks": True}))
    assert len(out["scorecard"]["checks"]) == 3


@respx.mock
async def test_project_packages_groups_and_ranks_verified_first():
    def v(name, version, prov, rel="SOURCE_REPO"):
        return {"versionKey": vk(name, version), "relationType": rel, "relationProvenance": prov}

    body = {"versions": [v("noise>1>left", "1", "UNVERIFIED_METADATA"), v("noise>1>left", "2", "UNVERIFIED_METADATA"), v("left", "1", "SLSA_ATTESTATION"), v("left", "2", "SLSA_ATTESTATION")]}
    respx.get(f"{BASE}/projects/github.com%2Fx%2Fleft:packageversions").mock(return_value=httpx.Response(200, json=body))
    out = data(await call("project_packages", {"project_id": "github.com/x/left"}))
    assert out["package_count"] == 2
    assert out["packages"][0]["name"] == "left" and out["packages"][0]["versions"] == 2


@respx.mock
async def test_lookup_hash_converts_hex_to_base64():
    route = respx.get(f"{BASE}/query").mock(return_value=httpx.Response(200, json={"results": [{"version": version_doc("left", "2.0.0", ["A-1"])}]}))
    out = data(await call("lookup_hash", {"hash_type": "SHA256", "hash_value": "ab" * 32}))
    params = route.calls.last.request.url.params
    assert params["hash.type"] == "SHA256"
    assert params["hash.value"] == "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s="
    assert out["matches"][0]["advisory_count"] == 1 and out["match_count"] == 1


async def test_lookup_hash_rejects_garbage():
    result = await call("lookup_hash", {"hash_type": "SHA1", "hash_value": "not a hash!"})
    assert result.is_error and "hex" in text(result)


@respx.mock
async def test_not_found_is_a_readable_tool_error():
    respx.get(f"{BASE}/systems/NPM/packages/nope").mock(return_value=httpx.Response(404, json={"error": "x"}))
    result = await call("package_overview", {"system": "npm", "name": "nope"})
    assert result.is_error and "Not found" in text(result)


@respx.mock
async def test_retries_on_429_then_succeeds():
    route = respx.get(f"{BASE}/advisories/A-1").mock(side_effect=[httpx.Response(429), httpx.Response(200, json=advisory_doc("A-1", 8.0))])
    out = data(await call("advisory", {"advisory_id": "A-1"}))
    assert route.call_count == 2 and out["severity"] == "high" and out["cvss3_vector"]


@respx.mock
async def test_persistent_rate_limit_and_timeout_messages(monkeypatch):
    monkeypatch.setenv("DEPSDEV_RETRIES", "1")
    respx.get(f"{BASE}/advisories/A-1").mock(return_value=httpx.Response(429))
    result = await call("advisory", {"advisory_id": "A-1"})
    assert result.is_error and "Rate limited" in text(result)
    respx.get(f"{BASE}/advisories/A-2").mock(side_effect=httpx.ConnectTimeout("slow"))
    result = await call("advisory", {"advisory_id": "A-2"})
    assert result.is_error and "timed out" in text(result)


@respx.mock
async def test_base_url_override_and_truncation(monkeypatch):
    monkeypatch.setenv("DEPSDEV_BASE_URL", "https://mirror.test/v3/")
    monkeypatch.setenv("DEPSDEV_MAX_CHARS", "300")
    big = {"packageKey": {}, "versions": [{"versionKey": vk("p", str(i)), "publishedAt": f"2020-01-{i % 28 + 1:02d}T00:00:00Z"} for i in range(200)]}
    respx.get("https://mirror.test/v3/systems/NPM/packages/p").mock(return_value=httpx.Response(200, json=big))
    out = text(await call("package_overview", {"system": "npm", "name": "p", "recent": 100}))
    assert "[truncated" in out


async def test_all_tools_are_registered_read_only():
    async with Client(server.mcp) as c:
        listed = (await c.list_tools()).tools
    names = {t.name for t in listed}
    assert names == {"package_overview", "version_details", "dependencies", "requirements", "audit_package", "advisory", "project_health", "project_packages", "lookup_hash"}
    assert all(t.annotations and t.annotations.read_only_hint for t in listed)
