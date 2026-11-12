"""Existing domain snapshots -> display-only projection; never cloud execution."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from sova_security.adapters.console_workload import (
    ConsolePlanBinding,
    project_security_snapshots,
)
from sova_security.contracts.commands import ContractError, ResourceScope
from sova_security.contracts.evidence import VerificationResult
from sova_security.contracts.graph import (
    SystemGraph,
    SystemResource,
    SystemRelation,
    ResourceKind,
    RelationKind,
    Portability,
)
from sova_security.domain.governance import ControlFamily
from sova_security.domain.posture import PostureFinding, FindingBasis
from sova_security.domain.security_events import SecuritySnapshot

NOW = datetime(2026, 11, 7, tzinfo=UTC)
BINDING = ConsolePlanBinding(
    "tenant", "app", "plan-console", "a" * 64, 3, "source", "target"
)


def snapshot(
    *,
    environment="source",
    result=VerificationResult.FAIL,
    origin="kubernetes_api",
    count=3,
):
    kinds = tuple(ResourceKind)
    resources = tuple(
        SystemResource(
            f"resource:{i}",
            f"private-label-{i}",
            ResourceScope("tenant", "app", environment, f"private-uid-{i}"),
            kinds[i % len(kinds)],
            "kubernetes",
            "private-location",
            f"revision-{i}",
            Portability.UNKNOWN,
        )
        for i in range(count)
    )
    graph = SystemGraph(
        "tenant",
        "app",
        7,
        origin,
        NOW,
        NOW + timedelta(seconds=60),
        resources,
        tuple(
            SystemRelation(
                resources[i].node_id, resources[i + 1].node_id, RelationKind.USES, True
            )
            for i in range(count - 1)
        ),
    )
    finding = PostureFinding(
        "control-test",
        next(iter(ControlFamily)),
        resources[0].scope,
        resources[0].resource_revision,
        result,
        FindingBasis.CONFIGURATION,
        "fixture_violation",
        "b" * 64,
        NOW,
        NOW + timedelta(seconds=60),
    )
    return SecuritySnapshot(graph, (finding,), "c" * 64)


def project(*snapshots, **changes):
    args = dict(stream_id="stream-fixture", revision=1, now=NOW, provenance="live")
    args.update(changes)
    return project_security_snapshots(BINDING, snapshots or (snapshot(),), **args)


def test_domain_graph_and_findings_are_projected_without_runtime_claims():
    doc = project(snapshot(), snapshot(environment="target"))
    assert doc["authorizes_execution"] is False
    assert len(doc["nodes"]) == 6 and len(doc["edges"]) == 4
    assert {n["lane"] for n in doc["nodes"]} == {"source", "target"}
    assert len({n["id"] for n in doc["nodes"]}) == 6
    assert sum(n["security"] == "warning" for n in doc["nodes"]) == 2
    assert all(n["health"] == "unknown" for n in doc["nodes"])
    assert all(e["state"] == "unknown" for e in doc["edges"])
    assert all(r["status"] == "unknown" for r in doc["responses"])
    assert not doc["events"]
    assert "private-" not in str(doc)


def test_configuration_pass_does_not_become_general_security_pass():
    doc = project(snapshot(result=VerificationResult.PASS))
    assert all(n["security"] == "unknown" for n in doc["nodes"])
    assert not doc["evidence"]


def test_local_graph_cannot_be_promoted_to_live():
    with pytest.raises(ContractError):
        project(snapshot(origin="local_demo"))
    assert (
        project(snapshot(origin="local_demo"), provenance="synthetic")["provenance"]
        == "synthetic"
    )


@pytest.mark.parametrize("origin", ["registration", "kubernetes_snapshot"])
def test_registered_or_saved_graph_is_not_live_discovery(origin):
    with pytest.raises(ContractError):
        project(snapshot(origin=origin))
    assert (
        project(snapshot(origin=origin), provenance="historical")["provenance"]
        == "historical"
    )


def test_unmatched_environment_is_rejected():
    with pytest.raises(ContractError):
        project(snapshot(environment="other"))


def test_duplicate_environment_and_excessive_scope_are_rejected():
    with pytest.raises(ContractError):
        project(snapshot(), snapshot())
    with pytest.raises(ContractError):
        project(snapshot(count=49))


def test_future_and_cross_tenant_bindings_are_rejected():
    with pytest.raises(ContractError):
        project(now=NOW - timedelta(seconds=1))
    with pytest.raises(ContractError):
        project_security_snapshots(
            replace(BINDING, tenant_id="other"),
            (snapshot(),),
            stream_id="s",
            revision=1,
            now=NOW,
            provenance="live",
        )


def test_expired_evidence_is_not_freshened_by_a_new_http_request():
    before = project()
    after = project(now=NOW + timedelta(minutes=10))
    assert before["observed_at"] == after["observed_at"]
    assert before["expires_at"] == after["expires_at"]


def test_replacement_changes_identity_binding_and_keeps_edge_identity_stable():
    old = snapshot(result=VerificationResult.PASS)
    resources = list(old.graph.resources)
    resources[0] = replace(resources[0], resource_revision="replacement-revision")
    new = SecuritySnapshot(
        replace(old.graph, resources=tuple(resources)), (), old.collection_digest
    )
    left, right = project(old), project(new)
    assert left["nodes"][0]["id"] == right["nodes"][0]["id"]
    assert left["nodes"][0]["resource_uid"] != right["nodes"][0]["resource_uid"]
    assert left["edges"][0]["id"] == right["edges"][0]["id"]
    assert left["edges"][0]["resource_uid"] != right["edges"][0]["resource_uid"]


def test_largest_supported_graph_is_bounded_and_all_kinds_preserved():
    doc = project(snapshot(count=48))
    assert len(doc["nodes"]) == 48
    assert max(n["row"] for n in doc["nodes"]) == 9
    assert {n["kind"] for n in doc["nodes"]} == {
        "app",
        "database",
        "storage",
        "worker",
        "queue",
        "identity",
        "secret",
        "ai",
        "observability",
        "edge",
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"revision": True},
        {"stream_id": "not/a/path"},
        {"revision": 0},
        {"revision": 2**53},
        {"provenance": "trusted"},
    ],
)
def test_unbounded_or_ambiguous_projection_metadata_is_rejected(changes):
    with pytest.raises(ContractError):
        project(**changes)
