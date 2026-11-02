from dataclasses import replace
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from governance_support import bundle, release_bundle
from sova_security.adapters.ed25519_evidence import Ed25519EvidenceSigner
from sova_security.adapters.hold_release_evidence import (
    HoldReleaseAuthority,
    hold_release_record,
)
from sova_security.contracts.commands import ContractError
from sova_security.domain.signed_evidence import VerifierTrust


@pytest.fixture
def authority(scope, now):
    _, plan, _, _, hold = bundle(scope, now)
    request, evidence = release_bundle(hold, plan.revisions, now)
    signer = Ed25519EvidenceSigner(
        Ed25519PrivateKey.generate(),
        issuer_id=request.approved_by,
        key_id="test-only-key",
    )
    record = hold_release_record(request, evidence_id="release-approval-test")
    trust = VerifierTrust(
        signer.issuer_id,
        signer.key_id,
        signer.public_key_hex,
        (scope,),
        (record.verifier_version,),
        now - timedelta(seconds=1),
        now + timedelta(minutes=10),
    )
    state = {
        "envelope": signer.sign(record, issued_at=now),
        "trust": trust,
        "revisions": request.revisions,
        "allowed": True,
        "clock": now,
        "late": lambda: None,
        "calls": 0,
    }

    def authorize(*_):
        state["calls"] += 1
        if state["calls"] == 2:
            state["late"]()
        return state["allowed"]

    verifier = HoldReleaseAuthority(
        envelope_provider=lambda _: state["envelope"],
        current_revisions=lambda _: state["revisions"],
        resolve_trust=lambda *_: state["trust"],
        authorize=authorize,
        clock=lambda: state["clock"],
    )
    return verifier, request, state


def test_current_scoped_approver_signature_binds_exact_release(authority):
    verifier, request, _ = authority
    assert verifier(request) is None
    assert not hasattr(request, "execution_authorized")


@pytest.mark.parametrize(
    "field",
    [
        "reason",
        "requested_by",
        "approved_by",
        "evidence_digest",
        "expected_revision",
        "scope",
        "revisions",
        "valid_until",
    ],
)
def test_same_signature_cannot_authorize_another_release(authority, field):
    verifier, request, _ = authority
    values = {
        "reason": "different-remediation",
        "requested_by": "another-responder",
        "approved_by": "another-approver",
        "evidence_digest": "0" * 64,
        "expected_revision": 2,
        "scope": replace(request.scope, resource_id="other-resource"),
        "revisions": replace(request.revisions, source="0" * 64),
        "valid_until": request.valid_until + timedelta(seconds=1),
    }
    with pytest.raises(ContractError):
        verifier(replace(request, **{field: values[field]}))


@pytest.mark.parametrize(
    "mode",
    [
        "revoked",
        "denied",
        "revision",
        "expired",
        "envelope",
        "wrong-version",
        "wrong-scope",
    ],
)
def test_live_revocation_and_late_change_cannot_release_containment(authority, mode):
    verifier, request, state = authority

    def late():
        if mode == "revoked":
            state["trust"] = replace(state["trust"], revoked=True)
        if mode == "denied":
            state["allowed"] = False
        if mode == "revision":
            state["revisions"] = replace(request.revisions, configuration="0" * 64)
        if mode == "expired":
            state["clock"] = request.valid_until
        if mode == "envelope":
            state["envelope"] = replace(state["envelope"], signature_hex="0" * 128)
        if mode == "wrong-version":
            state["trust"] = replace(
                state["trust"], allowed_verifiers=("unrelated-proof",)
            )
        if mode == "wrong-scope":
            state["trust"] = replace(
                state["trust"],
                allowed_scopes=(replace(request.scope, resource_id="other-resource"),),
            )

    state["late"] = late
    with pytest.raises(ContractError):
        verifier(request)
