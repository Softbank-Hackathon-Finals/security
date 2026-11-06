"""Project existing typed security snapshots into a read-only console document.

This is not a new policy, evidence verifier, graph collector, or executor. The
host must authenticate the producer and tenant/plan access before publishing the
bytes. Configuration PASS and event names never imply runtime isolation.
"""

from dataclasses import dataclass
from datetime import timedelta
import hashlib
import re

from sova_security.contracts.commands import ContractError, canonical_json, digest, utc
from sova_security.contracts.evidence import VerificationResult
from sova_security.domain.security_events import SecuritySnapshot

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_STAGES = (
    "detect",
    "hold",
    "approve",
    "isolate",
    "replace",
    "verify",
    "route",
    "recover",
)
_KINDS = {
    "service": "app",
    "database": "database",
    "storage": "storage",
    "worker": "worker",
    "queue": "queue",
    "identity": "identity",
    "secret": "secret",
    "ai": "ai",
    "observability": "observability",
    "edge": "edge",
}
_LABELS = {
    "service": "앱",
    "database": "데이터베이스",
    "storage": "파일 저장소",
    "worker": "작업자",
    "queue": "메시지 큐",
    "identity": "신원",
    "secret": "비밀 참조",
    "ai": "AI 서비스",
    "observability": "관측",
    "edge": "진입점",
}


def _require(condition):
    if not condition:
        raise ContractError("Invalid console snapshot binding")


def _opaque(prefix, value):
    return prefix + hashlib.sha256(value.encode()).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class ConsolePlanBinding:
    """Copy from the host's authenticated current plan, never browser arguments."""

    tenant_id: str
    application_id: str
    plan_id: str
    plan_digest: str
    plan_version: int
    source_environment_id: str
    target_environment_id: str

    def __post_init__(self):
        for value in (
            self.tenant_id,
            self.application_id,
            self.plan_id,
            self.source_environment_id,
            self.target_environment_id,
        ):
            _require(type(value) is str and bool(_ID.fullmatch(value)))
        digest(self.plan_digest)
        _require(type(self.plan_version) is int and 0 < self.plan_version <= 2**53 - 1)
        _require(self.source_environment_id != self.target_environment_id)


def project_security_snapshots(
    binding, snapshots, *, stream_id, revision, now, provenance
):
    """Use exact graph/resource revisions; emit only known configuration warnings.

    Relations remain registered/unknown (not observed traffic). Every health,
    isolation, approval, replacement and recovery state remains unconfirmed.
    Resource names/ARNs/paths are deliberately replaced by stable opaque IDs and
    kind labels; the caller can resolve friendly labels in its own registry.
    """
    _require(type(binding) is ConsolePlanBinding)
    _require(type(snapshots) is tuple and 1 <= len(snapshots) <= 2)
    _require(all(type(s) is SecuritySnapshot for s in snapshots))
    _require(type(stream_id) is str and bool(_ID.fullmatch(stream_id)))
    _require(type(revision) is int and 0 < revision <= 2**53 - 1)
    _require(provenance in {"live", "synthetic", "historical"})
    now = utc(now)
    _require(sum(len(s.graph.resources) for s in snapshots) <= 48)
    _require(sum(len(s.graph.relations) for s in snapshots) <= 96)
    environments = {
        binding.source_environment_id: "source",
        binding.target_environment_id: "target",
    }
    seen_environments = set()
    for snapshot in snapshots:
        graph = snapshot.graph
        _require(
            (graph.tenant_id, graph.application_id)
            == (binding.tenant_id, binding.application_id)
        )
        _require(graph.observed_at <= now)
        envs = {r.scope.environment_id for r in graph.resources}
        _require(
            len(envs) == 1
            and envs <= environments.keys()
            and not envs & seen_environments
        )
        seen_environments |= envs
        if graph.origin == "local_demo":
            _require(provenance == "synthetic")
        # A saved/registered graph cannot be relabelled as live discovery.
        if provenance == "live":
            _require(graph.origin == "kubernetes_api")
    observed = max(s.graph.observed_at for s in snapshots)
    expiry = min(
        *(s.graph.valid_until for s in snapshots), observed + timedelta(minutes=5)
    )
    _require(observed < expiry)
    result = {
        "kind": "console-workload.v1",
        "authorizes_execution": False,
        "plan_id": binding.plan_id,
        "plan_digest": binding.plan_digest,
        "plan_version": binding.plan_version,
        "stream_id": stream_id,
        "revision": revision,
        "provenance": provenance,
        "source_label": "보안 구성 관측 · 실행·격리 확인 아님",
        "observed_at": observed.isoformat(),
        "expires_at": expiry.isoformat(),
        "nodes": [],
        "edges": [],
        "evidence": [],
        "responses": [],
        "events": [],
    }
    for snapshot in sorted(
        snapshots, key=lambda s: s.graph.resources[0].scope.environment_id
    ):
        graph = snapshot.graph
        ids, revisions = {}, {}
        for index, resource in enumerate(graph.resources):
            # Both UID/resource identity and revision participate: replacement
            # under the same name cannot borrow a previous resource's proof.
            scope_key = canonical_json(resource.document["scope"])
            node_id = _opaque("resource-", scope_key)
            resource_uid = _opaque(
                "revision-", scope_key + "\n" + resource.resource_revision
            )
            ids[resource.node_id] = node_id
            revisions[resource.node_id] = resource_uid
            findings = [
                f
                for f in snapshot.findings
                if f.scope == resource.scope and f.result == VerificationResult.FAIL
            ]
            node = {
                "id": node_id,
                "label": f"{_LABELS[str(resource.kind)]} {index + 1}",
                "resource_uid": resource_uid,
                "detail": "등록된 자원 · 구성 관측과 실제 실행 상태는 별도 확인",
                "kind": _KINDS[str(resource.kind)],
                "lane": environments[resource.scope.environment_id],
                "column": index % 5,
                "row": index // 5,
                "health": "unknown",
                "security": "unknown",
                "health_evidence": None,
                "security_evidence": None,
            }
            _require(node["row"] <= 9)
            if findings:
                proof_id = _opaque(
                    "finding-", "\n".join(sorted(f.fingerprint for f in findings))
                )
                node.update(security="warning", security_evidence=proof_id)
                result["evidence"].append(
                    {
                        "id": proof_id,
                        "resource_id": node_id,
                        "resource_uid": resource_uid,
                        "kind": "security",
                        "outcome": "verified",
                        "summary": f"등록된 통제 위반 {len(findings)}건 · 공격·격리 완료 판정 아님",
                        "observed_at": graph.observed_at.isoformat(),
                        "expires_at": expiry.isoformat(),
                    }
                )
            result["nodes"].append(node)
        for relation in graph.relations:
            # Self-dependency is not useful as a response edge. Reject it rather
            # than omit an unsupported relation silently.
            _require(relation.source != relation.target)
            edge_id = _opaque(
                "relation-",
                graph.tenant_id
                + "\n"
                + graph.application_id
                + "\n"
                + graph.resources[0].scope.environment_id
                + "\n"
                + canonical_json(relation.document),
            )
            kind = "replication" if str(relation.kind) == "replicates" else "dependency"
            result["edges"].append(
                {
                    "id": edge_id,
                    "source": ids[relation.source],
                    "target": ids[relation.target],
                    "label": "등록된 의존성",
                    "kind": kind,
                    "resource_uid": _opaque(
                        "relation-revision-",
                        revisions[relation.source] + revisions[relation.target],
                    ),
                    "state": "unknown",
                    "evidence_id": None,
                }
            )
    result["responses"] = [
        {
            "stage": stage,
            "status": "unknown",
            "detail": "실행·승인·독립 검증 영수증 미연결",
            "node_ids": [],
            "evidence_id": None,
        }
        for stage in _STAGES
    ]
    # Provenance/authorization remains the host's job. No new decision, approval,
    # effect, command, credential, raw observation, or public URL is emitted.
    canonical_json(result, limit=120000)
    return result
