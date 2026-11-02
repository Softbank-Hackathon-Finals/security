"""Bind independent rehearsal receipts to the existing Ed25519 evidence trust.

Signing remains an independent verifier responsibility. This adapter does not
accept AI assertions, arbitrary public keys or a boolean 'sandbox passed'.
"""

import hashlib

from sova_security.adapters.ed25519_evidence import Ed25519EvidenceVerifier
from sova_security.contracts.commands import ContractError, canonical_json
from sova_security.contracts.evidence import (
    EvidenceRecord,
    RevisionSet,
    VerificationResult,
)
from sova_security.domain.remediation import evaluate_rehearsal
from sova_security.domain.signed_evidence import EvidenceEnvelope, VerifierTrust

VERIFIER_VERSION = "sova.security.rehearsal.v1"


def rehearsal_evidence(request, receipt, *, evidence_id):
    """Canonical record for an independent verifier to sign after its own tests."""
    decision = evaluate_rehearsal(request, receipt, now=receipt.issued_at)
    environment = hashlib.sha256(
        canonical_json(
            {"targets": [t.document for t in request.targets]}, limit=65536
        ).encode()
    ).hexdigest()
    return EvidenceRecord(
        evidence_id,
        request.request_id,
        request.proposal.scope,
        RevisionSet(
            request.proposal.base_source_digest,
            request.proposal.base_configuration_digest,
            request.proposal.policy_digest,
            environment,
        ),
        VERIFIER_VERSION,
        receipt.issued_at,
        decision.valid_until,
        VerificationResult.PASS if decision.allowed else VerificationResult.FAIL,
        "rehearsal:" + receipt.fingerprint,
        receipt.fingerprint,
    )


class RehearsalReceiptAuthority:
    def __init__(self, *, envelope_provider, resolve_trust, clock):
        self.envelope_provider = envelope_provider
        self.resolve_trust = resolve_trust
        self.clock = clock
        self.verifier = Ed25519EvidenceVerifier(resolve_trust)

    def __call__(self, actor, request, receipt):
        envelope = self.envelope_provider(actor, request, receipt)
        if not isinstance(envelope, EvidenceEnvelope) or not (
            envelope.issuer_id == receipt.issuer_id == request.verifier_issuer
        ):
            raise ContractError("Independent registered rehearsal envelope required")
        record = rehearsal_evidence(
            request, receipt, evidence_id=envelope.evidence.evidence_id
        )
        self.verifier.verify(envelope, expected_record=record, now=self.clock())
        trust = self.resolve_trust(envelope.issuer_id, envelope.key_id)
        if not isinstance(trust, VerifierTrust) or not {
            t.scope for t in request.targets
        }.issubset(trust.allowed_scopes):
            raise ContractError("Verifier is not authorized for every rehearsal target")
        trust.require_authorized(envelope, self.clock())
        # Do not keep a cached key authorization after an external registry lookup.
        self.verifier.verify(envelope, expected_record=record, now=self.clock())
        if self.resolve_trust(envelope.issuer_id, envelope.key_id) != trust:
            raise ContractError(
                "Rehearsal signer authority changed during verification"
            )
