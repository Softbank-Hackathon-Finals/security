from dataclasses import replace
from datetime import timedelta
import pytest

from modernization_support import rehearsal_bundle
from sova_security.contracts.commands import ContractError
from sova_security.contracts.evidence import VerificationResult as R
from sova_security.domain.remediation import (
    FileChange,
    Applicability,
    TargetRole,
    RehearsalTarget,
    TestedArtifact as Artifact,
    evaluate_rehearsal,
)
from sova_security.application.remediation import (
    RehearsalAdmissionService,
    require_proposal_binding,
)


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "../app.py",
        "src/../app.py",
        "src//app.py",
        "src\\app.py",
        ".github/workflows/ci.yml",
        "Tests/golden.py",
        "verifier/main.py",
        ".env",
        "src/.env.prod",
        "src/key.PEM",
        "src/evil;cmd.py",
        "src/\u202eapp.py",
        "C:/app.py",
        "src/app.py/",
    ],
)
def test_patch_cannot_modify_protected_or_ambiguous_paths(path):
    with pytest.raises(ContractError):
        FileChange(path, "a" * 64, "b" * 64)


def test_full_receipt_preserves_baseline_and_independent_artifact_bindings(scope, now):
    _, _, request, receipt = rehearsal_bundle(scope, now)
    decision = evaluate_rehearsal(request, receipt, now=now + timedelta(seconds=4))
    assert decision.allowed and decision.reasons == ()
    assert decision.valid_until == request.valid_until
    assert decision.request_digest == request.fingerprint


@pytest.mark.parametrize(
    "field",
    [
        "request_digest",
        "proposal_digest",
        "runner_image_digest",
        "verifier_image_digest",
        "test_bundle_digest",
        "egress_policy_digest",
    ],
)
def test_any_changed_binding_prevents_admission(scope, now, field):
    _, _, request, receipt = rehearsal_bundle(scope, now)
    changed = replace(receipt, **{field: "f" * 64})
    assert not evaluate_rehearsal(
        request, changed, now=now + timedelta(seconds=4)
    ).allowed


@pytest.mark.parametrize(
    "field,value",
    [
        ("issuer_id", "unregistered"),
        ("no_production_credentials", False),
        ("metadata_denied", R.UNKNOWN),
        ("egress_denied", R.FAIL),
        ("elapsed_seconds", 121),
        ("peak_memory_mib", 513),
    ],
)
def test_protection_claims_and_resource_limits_require_verified_results(
    scope, now, field, value
):
    _, _, request, receipt = rehearsal_bundle(scope, now)
    assert not evaluate_rehearsal(
        request, replace(receipt, **{field: value}), now=now + timedelta(seconds=4)
    ).allowed


def test_missing_test_wrong_image_and_false_baseline_are_distinct_failures(scope, now):
    _, _, request, receipt = rehearsal_bundle(scope, now)

    def decision(proofs):
        return evaluate_rehearsal(
            request, replace(receipt, proofs=proofs), now=now + timedelta(seconds=4)
        )

    assert not decision(receipt.proofs[:-1]).allowed
    changed = list(receipt.proofs)
    after = next(i for i, p in enumerate(changed) if p.phase == "after")
    changed[after] = replace(changed[after], image_digest="f" * 64)
    assert not decision(tuple(changed)).allowed
    changed = list(receipt.proofs)
    before = next(
        i
        for i, p in enumerate(changed)
        if p.phase == "before" and p.test_id.startswith("security-fix:")
    )
    changed[before] = replace(changed[before], result=R.PASS)
    assert not decision(tuple(changed)).allowed


def test_file_manifest_and_target_scope_cannot_be_silently_expanded(scope, now):
    _, _, request, receipt = rehearsal_bundle(scope, now)
    changed = replace(
        receipt, changed_files=(FileChange("src/other.py", "1" * 64, "2" * 64),)
    )
    assert not evaluate_rehearsal(
        request, changed, now=now + timedelta(seconds=4)
    ).allowed
    proof = replace(receipt.proofs[0], scope=replace(scope, tenant_id="other"))
    changed = replace(receipt, proofs=(proof, *receipt.proofs[1:]))
    assert not evaluate_rehearsal(
        request, changed, now=now + timedelta(seconds=4)
    ).allowed


def test_source_only_does_not_claim_target_compatibility(scope, now):
    _, _, request, receipt = rehearsal_bundle(scope, now)
    assert len(request.targets) == 1
    with pytest.raises(ContractError, match="coverage"):
        replace(
            request,
            proposal=replace(request.proposal, applicability=Applicability.BOTH),
        )
    with pytest.raises(ContractError, match="file scope"):
        replace(
            request, profile=replace(request.profile, allowed_files=("src/other.py",))
        )


def test_both_requires_destination_tests_and_detects_tls_style_regression(scope, now):
    _, _, request, receipt = rehearsal_bundle(scope, now)
    target_scope = replace(
        scope, environment_id="destination", resource_id="destination-app"
    )
    proposal = replace(request.proposal, applicability=Applicability.BOTH)
    target = RehearsalTarget(target_scope, TargetRole.TARGET, "a" * 64, "c" * 64)
    requirements = (
        *request.requirements,
        *(replace(r, scope=target_scope) for r in request.requirements),
    )
    both = replace(
        request,
        proposal=proposal,
        targets=(*request.targets, target),
        requirements=requirements,
    )
    proofs = list(receipt.proofs)
    for p in receipt.proofs:
        proofs.append(
            replace(
                p,
                scope=target_scope,
                image_digest="c" * 64 if p.phase == "before" else "0" * 64,
            )
        )
    checked = replace(
        receipt,
        request_digest=both.fingerprint,
        proposal_digest=proposal.fingerprint,
        artifacts=(
            *receipt.artifacts,
            Artifact(target_scope, "0" * 64, "f" * 64, "c" * 64, "1" * 64),
        ),
        proofs=tuple(proofs),
    )
    assert evaluate_rehearsal(both, checked, now=now + timedelta(seconds=4)).allowed
    failed = tuple(
        replace(p, result=R.FAIL)
        if p.scope == target_scope and p.test_id == "compatibility"
        else p
        for p in checked.proofs
    )
    result = evaluate_rehearsal(
        both, replace(checked, proofs=failed), now=now + timedelta(seconds=4)
    )
    assert (
        not result.allowed
        and "missing-or-failed-proof:compatibility:after" in result.reasons
    )


def test_unverified_baseline_cannot_be_hidden_by_new_test_names(scope, now):
    _, _, request, _ = rehearsal_bundle(scope, now)
    changed = tuple(
        replace(r, test_id="arbitrary") if r.test_id.startswith("security-fix:") else r
        for r in request.requirements
    )
    with pytest.raises(ContractError, match="obligations"):
        replace(request, requirements=changed)


def test_proposal_cannot_extend_observed_assessment_validity(scope, now):
    inputs, assessment, request, _ = rehearsal_bundle(scope, now)
    with pytest.raises(ContractError, match="validity was extended"):
        require_proposal_binding(
            replace(
                request.proposal,
                valid_until=assessment.valid_until + timedelta(seconds=1),
            ),
            inputs[0],
            assessment,
            now=now,
        )


def admission(scope, now, *, receipt_auth=lambda *_: None, mutate=None):
    inputs, assessment, request, receipt = rehearsal_bundle(scope, now)
    state = {"inputs": inputs, "request": request, "assessment": assessment}

    def authenticate(*args):
        result = receipt_auth(*args)
        if mutate:
            mutate(state)
        return result

    service = RehearsalAdmissionService(
        authorize=lambda *_: None,
        authenticate_input=lambda *_: None,
        authenticate_receipt=authenticate,
        current_inputs=lambda _: state["inputs"],
        current_request=lambda *_: state["request"],
        current_assessment=lambda *_: state["assessment"],
        target_inventory=lambda _: state.get("target", state["inputs"][0]),
        clock=lambda: now + timedelta(seconds=4),
    )
    return service, state, request, receipt


def test_independent_authority_is_required_not_just_a_valid_receipt_hash(scope, now):
    def deny(*_):
        raise ContractError("Untrusted verifier")

    service, _, request, receipt = admission(scope, now, receipt_auth=deny)
    with pytest.raises(ContractError, match="Untrusted"):
        service.verify("actor", request=request, receipt=receipt)


def test_changed_input_after_receipt_verification_cannot_be_admitted(scope, now):
    def mutate(state):
        state["inputs"] = (
            *state["inputs"][:3],
            replace(state["inputs"][3], revision=2),
        )

    service, _, request, receipt = admission(scope, now, mutate=mutate)
    with pytest.raises(ContractError, match="changed during"):
        service.verify("actor", request=request, receipt=receipt)


def test_admission_accepts_only_the_bound_persisted_assessment(scope, now):
    service, state, request, receipt = admission(scope, now)
    assert service.verify("actor", request=request, receipt=receipt).allowed
    state["assessment"] = replace(state["assessment"], scan_digest="f" * 64)
    with pytest.raises(ContractError, match="no longer current"):
        service.verify("actor", request=request, receipt=receipt)


def test_false_receipt_authentication_and_late_revocation_are_denied(scope, now):
    service, _, request, receipt = admission(scope, now, receipt_auth=lambda *_: False)
    with pytest.raises(ContractError, match="did not accept"):
        service.verify("actor", request=request, receipt=receipt)
    count = {"n": 0}

    def revoke_on_second_verification(state):
        count["n"] += 1
        if count["n"] == 2:
            state["request"] = None

    service, _, request, receipt = admission(
        scope, now, mutate=revoke_on_second_verification
    )
    with pytest.raises(ContractError, match="before final"):
        service.verify("actor", request=request, receipt=receipt)


def test_request_does_not_allow_proposer_as_independent_verifier(scope, now):
    _, _, request, _ = rehearsal_bundle(scope, now)
    with pytest.raises(ContractError, match="Independent"):
        replace(request, verifier_issuer=request.proposal.created_by)


def test_target_revision_is_checked_even_when_source_authority_is_unchanged(scope, now):
    service, state, request, receipt = admission(scope, now)
    state["target"] = replace(state["inputs"][0], resource_revision="drifted")
    with pytest.raises(ContractError, match="target inventory changed"):
        service.verify("actor", request=request, receipt=receipt)


@pytest.mark.parametrize("subject", ["inventory", "scan", "request", "assessment"])
def test_unchanged_bytes_do_not_hide_revoked_input_authority(scope, now, subject):
    revoked = {"digest": None}

    def revoke(state):
        revoked["digest"] = {
            "inventory": state["inputs"][0].fingerprint,
            "scan": state["inputs"][1].fingerprint,
            "request": state["request"].fingerprint,
            "assessment": state["assessment"].fingerprint,
        }[subject]

    service, _, request, receipt = admission(scope, now, mutate=revoke)
    service.authenticate_input = lambda actor, scope, value: (
        value.fingerprint != revoked["digest"]
    )
    with pytest.raises(ContractError, match="did not accept"):
        service.verify("actor", request=request, receipt=receipt)


@pytest.mark.parametrize(
    "parent,child",
    [("src/app.py", "src/app.py/hidden.py"), ("src/App", "src/app/nested.py")],
)
def test_regular_file_manifest_cannot_alias_another_files_parent(
    scope, now, parent, child
):
    _, _, request, _ = rehearsal_bundle(scope, now)
    with pytest.raises(ContractError, match="directory"):
        replace(
            request.proposal,
            changes=(
                FileChange(parent, "a" * 64, "b" * 64),
                FileChange(child, "c" * 64, "d" * 64),
            ),
        )
