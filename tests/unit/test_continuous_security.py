from dataclasses import replace
from datetime import timedelta

import pytest

from governance_support import MemoryHolds
from modernization_support import rehearsal_bundle
from sova_security.adapters.modernization_codec import decode, encode
from sova_security.application.assessment import AssessmentService
from sova_security.application.continuous_security import ContinuousSecurityMonitor
from sova_security.contracts.commands import ContractError
from sova_security.domain.assessment import Compromise
from sova_security.domain.continuous_security import (
    RuntimeSecurityBaseline,
)
from sova_security.domain.governance import SecurityHold
from sova_security.domain.remediation import TestedArtifact as Artifact
from sova_security.ports.modernization import StoredSecurityArtifact


@pytest.fixture
def monitor(scope, now):
    inputs, baseline_assessment, _, _ = rehearsal_bundle(scope, now)
    inventory = inputs[0]
    baseline = RuntimeSecurityBaseline(
        scope,
        "e" * 64,
        Artifact(
            scope,
            inventory.image_digest,
            inventory.source_digest,
            inventory.configuration_digest,
            "f" * 64,
        ),
        inventory.resource_revision,
        baseline_assessment,
        now + timedelta(seconds=1),
        now + timedelta(hours=1),
    )
    state = {
        "inputs": inputs,
        "baseline": baseline,
        "stored": {},
        "allowed": True,
        "store-fails": False,
        "input-trusted": True,
        "after-store": lambda: None,
    }

    class Repo:
        tenant_id = scope.tenant_id

        def register(self, subject, value, *, actor_id):
            if state["store-fails"]:
                raise RuntimeError("Synthetic artifact outage")
            receipt = StoredSecurityArtifact(subject, value, 1, False)
            state["stored"][value.fingerprint] = receipt
            state["after-store"]()
            return receipt

        def get(self, subject, fingerprint):
            return state["stored"][fingerprint]

    class Holds(MemoryHolds):
        def open_incident(self, subject, reason, actor):
            for value in self.active_holds(subject.application_id):
                if value.hold.scope == subject and value.hold.reason == reason:
                    return value, False
            hold = SecurityHold(
                "incident-" + str(len(self.values)), subject, actor, reason, now
            )
            return self.open_hold(hold), True

    holds = Holds(scope.tenant_id, now)

    def authorize(*_):
        return state["allowed"]

    assessment = AssessmentService(
        authorize=authorize,
        authenticate_input=lambda *_: state["input-trusted"],
        current_inputs=lambda _: state["inputs"],
        clock=lambda: now + timedelta(seconds=4),
    )
    service = ContinuousSecurityMonitor(
        assessment_service=assessment,
        current_inputs=lambda _: state["inputs"],
        baseline_provider=lambda _: state["baseline"],
        authenticate_baseline=lambda _: None,
        artifacts=Repo(),
        holds=holds,
        authorize=authorize,
        clock=lambda: now + timedelta(seconds=4),
    )
    return service, state, holds


def test_steady_state_is_a_review_not_a_mutation_permit(monitor, scope):
    service, state, holds = monitor
    review = service.run_once("monitor", scope=scope)
    assert review.triggers == () and not holds.active_holds(scope.application_id)
    assert (
        "allowed" not in review.document
        and "execution_authorized" not in review.document
    )
    assert decode(encode(review).encode()) == review
    assert decode(encode(state["baseline"]).encode()) == state["baseline"]


def drift(state, case):
    inventory, scan, exposure, policy = state["inputs"]
    if case in {"image", "source", "configuration"}:
        inventory = replace(inventory, **{case + "_digest": "0" * 64})
    if case == "revision":
        inventory = replace(inventory, resource_revision="unapproved-change")
    scan = replace(
        scan,
        inventory_digest=inventory.fingerprint,
        image_digest=inventory.image_digest,
    )
    exposure = replace(
        exposure,
        inventory_digest=inventory.fingerprint,
        resource_revision=inventory.resource_revision,
    )
    if case == "new-risk":
        scan = replace(
            scan,
            findings=(
                *scan.findings,
                replace(scan.findings[0], advisory_id="SOVA-TEST-NEW"),
            ),
        )
    if case == "unknown":
        exposure = replace(exposure, compromise=Compromise.UNKNOWN)
    state["inputs"] = (inventory, scan, exposure, policy)


@pytest.mark.parametrize(
    "case", ["image", "source", "configuration", "revision", "new-risk", "unknown"]
)
def test_drift_opens_deduplicated_holds_without_patching_or_releasing(
    monitor, scope, case
):
    service, state, holds = monitor
    drift(state, case)
    review = service.run_once("monitor", scope=scope)
    assert review.triggers
    first = holds.active_holds(scope.application_id)
    assert first
    service.run_once("monitor", scope=scope)
    assert holds.active_holds(scope.application_id) == first
    # A later clean sample is not privileged incident release.
    state["inputs"] = rehearsal_bundle(scope, state["baseline"].assessment.assessed_at)[
        0
    ]
    service.run_once("monitor", scope=scope)
    assert holds.active_holds(scope.application_id) == first


def test_audit_outage_does_not_undo_a_detected_security_hold(monitor, scope):
    service, state, holds = monitor
    drift(state, "image")
    state["store-fails"] = True
    with pytest.raises(RuntimeError, match="outage"):
        service.run_once("monitor", scope=scope)
    assert holds.active_holds(scope.application_id)


def test_denied_monitoring_and_expired_baseline_do_not_return_healthy(
    monitor, scope, now
):
    service, state, _ = monitor
    state["allowed"] = False
    with pytest.raises(ContractError):
        service.run_once("monitor", scope=scope)
    state["allowed"] = True
    state["baseline"] = replace(
        state["baseline"], monitor_until=now + timedelta(seconds=3)
    )
    with pytest.raises(ContractError, match="expired"):
        service.run_once("monitor", scope=scope)


def test_false_baseline_authentication_cannot_create_a_monitoring_result(
    monitor, scope
):
    service, state, holds = monitor
    service.authenticate_baseline = lambda _: False
    with pytest.raises(ContractError):
        service.run_once("monitor", scope=scope)
    assert not state["stored"] and not holds.active_holds(scope.application_id)


def test_input_signer_revoked_after_audit_store_cannot_return_a_healthy_review(
    monitor, scope
):
    service, state, holds = monitor
    state["after-store"] = lambda: state.update({"input-trusted": False})
    with pytest.raises(ContractError):
        service.run_once("monitor", scope=scope)
    assert not holds.active_holds(scope.application_id)


def test_late_untrusted_inputs_preserve_already_recorded_containment(monitor, scope):
    service, state, holds = monitor
    drift(state, "image")
    state["after-store"] = lambda: state.update({"input-trusted": False})
    with pytest.raises(ContractError):
        service.run_once("monitor", scope=scope)
    assert holds.active_holds(scope.application_id)
