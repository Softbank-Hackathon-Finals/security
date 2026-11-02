from dataclasses import replace
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from modernization_support import rehearsal_bundle
from sova_security.adapters.assessment_evidence import (
    AssessmentInputAuthority,
    assessment_input_record,
)
from sova_security.adapters.ed25519_evidence import Ed25519EvidenceSigner
from sova_security.adapters.modernization_codec import kind_of
from sova_security.adapters.rehearsal_evidence import (
    RehearsalReceiptAuthority,
    rehearsal_evidence,
    VERIFIER_VERSION,
)
from sova_security.application.assessment import AssessmentService
from sova_security.application.remediation import RehearsalAdmissionService
from sova_security.contracts.commands import ContractError
from sova_security.contracts.evidence import RevisionSet
from sova_security.domain.signed_evidence import VerifierTrust


def authority_bundle(scope, now):
    inputs, assessment, request, receipt = rehearsal_bundle(scope, now)
    revisions = RevisionSet(
        inputs[0].source_digest,
        inputs[0].configuration_digest,
        inputs[3].fingerprint,
        "e" * 64,
    )
    values = (*inputs, assessment, request)
    state = {
        "envelopes": {},
        "trusts": {},
        "issuers": {},
        "allowed": True,
        "revisions": revisions,
    }
    for value in values:
        kind = kind_of(value)
        signer = Ed25519EvidenceSigner(
            Ed25519PrivateKey.generate(),
            issuer_id="issuer-" + kind,
            key_id="test-only-key",
        )
        record = assessment_input_record(
            value, revisions=revisions, evidence_id="proof-" + kind
        )
        state["envelopes"][value.fingerprint] = signer.sign(
            record, issued_at=now + timedelta(seconds=3)
        )
        state["trusts"][signer.issuer_id] = VerifierTrust(
            signer.issuer_id,
            signer.key_id,
            signer.public_key_hex,
            (scope,),
            (record.verifier_version,),
            now - timedelta(seconds=1),
            now + timedelta(minutes=30),
        )
        state["issuers"][kind] = (signer.issuer_id,)
    authority = AssessmentInputAuthority(
        envelope_provider=lambda actor, scope, value: state["envelopes"][
            value.fingerprint
        ],
        current_revisions=lambda _: state["revisions"],
        issuers_for=lambda scope, kind: state["issuers"][kind],
        resolve_trust=lambda issuer, key: state["trusts"][issuer],
        authorize=lambda *_: state["allowed"],
        clock=lambda: now + timedelta(seconds=4),
    )
    return authority, state, inputs, assessment, request, receipt


def test_actual_signatures_connect_existing_assessment_and_rehearsal_callbacks(
    scope, now
):
    authority, _, inputs, assessment, request, receipt = authority_bundle(scope, now)
    service = AssessmentService(
        authorize=lambda *_: None,
        authenticate_input=authority,
        current_inputs=lambda _: inputs,
        clock=lambda: now + timedelta(seconds=4),
    )
    result = service.assess(
        "operator", scope=scope, expected_inputs=tuple(v.fingerprint for v in inputs)
    )
    assert result.complete
    signer = Ed25519EvidenceSigner(
        Ed25519PrivateKey.generate(),
        issuer_id=request.verifier_issuer,
        key_id="independent-receipt-key",
    )
    receipt_record = rehearsal_evidence(
        request, receipt, evidence_id="independent-receipt"
    )
    receipt_envelope = signer.sign(receipt_record, issued_at=receipt.issued_at)
    receipt_trust = VerifierTrust(
        signer.issuer_id,
        signer.key_id,
        signer.public_key_hex,
        (scope,),
        (VERIFIER_VERSION,),
        now - timedelta(seconds=1),
        now + timedelta(minutes=30),
    )
    receipt_authority = RehearsalReceiptAuthority(
        envelope_provider=lambda *_: receipt_envelope,
        resolve_trust=lambda *_: receipt_trust,
        clock=lambda: now + timedelta(seconds=4),
    )
    admission = RehearsalAdmissionService(
        authorize=lambda *_: None,
        authenticate_input=authority,
        authenticate_receipt=receipt_authority,
        current_inputs=lambda _: inputs,
        current_request=lambda *_: request,
        current_assessment=lambda *_: assessment,
        target_inventory=lambda _: inputs[0],
        clock=lambda: now + timedelta(seconds=4),
    )
    assert admission.verify("operator", request=request, receipt=receipt).allowed


@pytest.mark.parametrize(
    "mode",
    [
        "revoked",
        "wrong-key",
        "wrong-scope",
        "wrong-kind",
        "issuer-removed",
        "revision",
        "false-auth",
    ],
)
def test_registered_input_bytes_never_override_current_authority(scope, now, mode):
    authority, state, inputs, _, _, _ = authority_bundle(scope, now)
    value = inputs[0]
    issuer = state["envelopes"][value.fingerprint].issuer_id
    trust = state["trusts"][issuer]
    if mode == "revoked":
        state["trusts"][issuer] = replace(trust, revoked=True)
    if mode == "wrong-key":
        state["trusts"][issuer] = replace(trust, public_key_hex="0" * 64)
    if mode == "wrong-scope":
        state["trusts"][issuer] = replace(
            trust, allowed_scopes=(replace(scope, application_id="foreign"),)
        )
    if mode == "wrong-kind":
        state["trusts"][issuer] = replace(
            trust, allowed_verifiers=("sova.security.assessment-input.risk-policy.v1",)
        )
    if mode == "issuer-removed":
        state["issuers"][kind_of(value)] = ("another-issuer",)
    if mode == "revision":
        state["revisions"] = replace(state["revisions"], policy="f" * 64)
    if mode == "false-auth":
        state["allowed"] = False
    with pytest.raises(ContractError):
        authority("operator", scope, value)


def test_caller_scope_cannot_relabel_signed_asset(scope, now):
    authority, _, inputs, _, _, _ = authority_bundle(scope, now)
    with pytest.raises(ContractError, match="crosses scope"):
        authority("operator", replace(scope, resource_id="other"), inputs[0])


def test_late_revoke_without_changing_the_input_is_rejected(scope, now):
    authority, state, inputs, _, _, _ = authority_bundle(scope, now)
    issuer = state["envelopes"][inputs[0].fingerprint].issuer_id
    calls = {"n": 0}

    def resolve(name, key):
        calls["n"] += 1
        if calls["n"] == 3:
            state["trusts"][name] = replace(state["trusts"][name], revoked=True)
        return state["trusts"][name]

    authority.resolve_trust = resolve
    authority.verifier.resolve_trust = resolve
    with pytest.raises(ContractError, match="revoked"):
        authority("operator", scope, inputs[0])
    assert state["trusts"][issuer].revoked


def test_unsupported_arbitrary_document_cannot_obtain_a_signature_role(scope, now):
    authority, _, _, _, _, receipt = authority_bundle(scope, now)
    with pytest.raises(ContractError, match="Unsupported"):
        authority("operator", scope, receipt)
