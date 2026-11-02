from dataclasses import replace
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from modernization_support import rehearsal_bundle
from sova_security.adapters.ed25519_evidence import Ed25519EvidenceSigner
from sova_security.adapters.rehearsal_evidence import (
    RehearsalReceiptAuthority,
    rehearsal_evidence,
    VERIFIER_VERSION,
)
from sova_security.contracts.commands import ContractError
from sova_security.domain.signed_evidence import VerifierTrust


def signed_bundle(scope, now):
    _, _, request, receipt = rehearsal_bundle(scope, now)
    signer = Ed25519EvidenceSigner(
        Ed25519PrivateKey.generate(),
        issuer_id=request.verifier_issuer,
        key_id="test-verifier-key",
    )
    trust = VerifierTrust(
        signer.issuer_id,
        signer.key_id,
        signer.public_key_hex,
        (scope,),
        (VERIFIER_VERSION,),
        now - timedelta(seconds=1),
        now + timedelta(minutes=10),
    )
    record = rehearsal_evidence(
        request, receipt, evidence_id="registered-rehearsal-proof"
    )
    envelope = signer.sign(record, issued_at=receipt.issued_at)
    return request, receipt, signer, trust, envelope


def test_real_signature_authenticates_the_entire_receipt_and_test_bundle(scope, now):
    request, receipt, _, trust, envelope = signed_bundle(scope, now)
    authority = RehearsalReceiptAuthority(
        envelope_provider=lambda *_: envelope,
        resolve_trust=lambda *_: trust,
        clock=lambda: now + timedelta(seconds=4),
    )
    assert authority("operator", request, receipt) is None
    with pytest.raises(ContractError):
        authority("operator", request, replace(receipt, test_bundle_digest="f" * 64))
    with pytest.raises(ContractError):
        authority("operator", request, replace(receipt, peak_memory_mib=1024))


def test_revoked_or_wrong_scope_keys_never_authenticate_rehearsal(scope, now):
    request, receipt, _, trust, envelope = signed_bundle(scope, now)
    for revoked in (
        replace(trust, revoked=True),
        replace(trust, allowed_scopes=(replace(scope, tenant_id="other"),)),
    ):
        authority = RehearsalReceiptAuthority(
            envelope_provider=lambda *_: envelope,
            resolve_trust=lambda *_: revoked,
            clock=lambda: now + timedelta(seconds=4),
        )
        with pytest.raises(ContractError):
            authority("operator", request, receipt)


def test_key_material_cannot_change_between_signature_and_scope_checks(scope, now):
    request, receipt, _, trust, envelope = signed_bundle(scope, now)
    other = Ed25519EvidenceSigner(
        Ed25519PrivateKey.generate(), issuer_id=trust.issuer_id, key_id=trust.key_id
    )
    calls = {"n": 0}

    def resolve(*_):
        calls["n"] += 1
        return (
            trust
            if calls["n"] == 1
            else replace(trust, public_key_hex=other.public_key_hex)
        )

    authority = RehearsalReceiptAuthority(
        envelope_provider=lambda *_: envelope,
        resolve_trust=resolve,
        clock=lambda: now + timedelta(seconds=4),
    )
    with pytest.raises(ContractError, match="signature"):
        authority("operator", request, receipt)
