from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest

from modernization_support import rehearsal_bundle
from sova_security.application.modernization import SecurityModernizationService
from sova_security.application.remediation import RehearsalAdmissionService
from sova_security.application.assessment import AssessmentService
from sova_security.contracts.commands import ContractError
from sova_security.contracts.repositories import RepositoryConflict
from sova_security.ports.modernization import StoredSecurityArtifact


@pytest.fixture
def modernization(scope, now):
    inputs, assessment, request, receipt = rehearsal_bundle(scope, now)
    state = {
        "artifacts": {},
        "plans": [],
        "allowed": True,
        "at": now + timedelta(seconds=4),
    }

    def authorize(*_):
        return state["allowed"]

    class Repository:
        tenant_id = scope.tenant_id

        def get(self, current_scope, fingerprint):
            saved = state["artifacts"][fingerprint]
            if saved.revoked:
                raise RepositoryConflict("revoked")
            return saved

        def register(self, current_scope, value, *, actor_id):
            saved = StoredSecurityArtifact(current_scope, value, 1, False)
            state["artifacts"][value.fingerprint] = saved
            return saved

    repo = Repository()
    repo.register(scope, request, actor_id="operator")
    repo.register(scope, receipt, actor_id="verifier")
    rehearsal = RehearsalAdmissionService(
        authorize=authorize,
        authenticate_input=lambda *_: None,
        authenticate_receipt=lambda *_: None,
        current_inputs=lambda _: inputs,
        current_request=lambda *_: request,
        current_assessment=lambda *_: assessment,
        target_inventory=lambda _: inputs[0],
        clock=lambda: state["at"],
    )
    service = SecurityModernizationService(
        artifacts=repo,
        assessment=AssessmentService(
            authorize=authorize,
            authenticate_input=lambda *_: None,
            current_inputs=lambda _: inputs,
            clock=lambda: state["at"],
        ),
        rehearsal=rehearsal,
        lifecycle=SimpleNamespace(save_plan=state["plans"].append),
        registered_adapters=lambda _: {scope: "registered-oci-adapter"},
        authorize=authorize,
        clock=lambda: state["at"],
    )
    return service, state, request, receipt, inputs


def test_host_api_records_assessment_review_and_unapproved_plan(modernization, scope):
    service, state, request, receipt, inputs = modernization
    result = service.assess(
        "operator", scope=scope, expected_inputs=tuple(i.fingerprint for i in inputs)
    )
    assert result.complete
    decision = service.review_rehearsal(
        "operator",
        scope=scope,
        request_digest=request.fingerprint,
        receipt_digest=receipt.fingerprint,
    )
    assert decision.allowed
    plan, binding = service.prepare_patch(
        "operator",
        scope=scope,
        request_digest=request.fingerprint,
        receipt_digest=receipt.fingerprint,
        plan_id="patch-1",
        execution_scope=scope,
    )
    assert state["plans"] == [plan]
    assert state["artifacts"][binding.fingerprint].value == binding
    assert (
        service.inspect("operator", scope=scope, fingerprint=decision.fingerprint)
        == decision
    )
    assert not hasattr(plan, "approved_by")


@pytest.mark.parametrize(
    "case", ["deny", "tenant", "wrong-resource", "revoked", "wrong-kind"]
)
def test_host_api_never_uses_arbitrary_client_authority(modernization, scope, case):
    service, state, request, receipt, _ = modernization
    current_scope = scope
    if case == "deny":
        state["allowed"] = False
    if case == "tenant":
        current_scope = replace(scope, tenant_id="other")
    if case == "wrong-resource":
        current_scope = replace(scope, resource_id="other")
    if case == "revoked":
        state["artifacts"][request.fingerprint] = replace(
            state["artifacts"][request.fingerprint], revoked=True
        )
    if case == "wrong-kind":
        state["artifacts"][request.fingerprint] = StoredSecurityArtifact(
            scope, receipt, 1, False
        )
    with pytest.raises((ContractError, RepositoryConflict)):
        service.prepare_patch(
            "operator",
            scope=current_scope,
            request_digest=request.fingerprint,
            receipt_digest=receipt.fingerprint,
            plan_id="patch-1",
            execution_scope=scope,
        )
    assert state["plans"] == []


def test_saved_plan_without_binding_is_inert_on_partial_persistence(
    modernization, scope
):
    service, state, request, receipt, _ = modernization
    original = service.artifacts.register

    def register(*args, **kwargs):
        if state["plans"]:
            raise RuntimeError("Synthetic DB outage after plan save")
        return original(*args, **kwargs)

    service.artifacts.register = register
    with pytest.raises(RuntimeError, match="DB outage"):
        service.prepare_patch(
            "operator",
            scope=scope,
            request_digest=request.fingerprint,
            receipt_digest=receipt.fingerprint,
            plan_id="patch-1",
            execution_scope=scope,
        )
    assert len(state["plans"]) == 1
    assert not any(
        type(s.value).__name__ == "PatchExecutionBinding"
        for s in state["artifacts"].values()
    )


def test_revocation_while_verifying_receipt_stops_persistence(modernization, scope):
    service, state, request, receipt, _ = modernization

    def revoke(*_):
        state["artifacts"][request.fingerprint] = replace(
            state["artifacts"][request.fingerprint], revoked=True
        )

    service.rehearsal.authenticate_receipt = revoke
    with pytest.raises(RepositoryConflict):
        service.review_rehearsal(
            "operator",
            scope=scope,
            request_digest=request.fingerprint,
            receipt_digest=receipt.fingerprint,
        )
