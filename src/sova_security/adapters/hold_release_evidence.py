"""Bind a containment release approval to an existing scoped signing key.

This is not a login or human-presence proof. The host maps an authenticated
security approver to its registered issuer and keeps signing keys outside agents.
"""

import hashlib

from sova_security.adapters.ed25519_evidence import Ed25519EvidenceVerifier
from sova_security.contracts.authority import require_accept
from sova_security.contracts.commands import ContractError, canonical_json, utc
from sova_security.contracts.evidence import EvidenceRecord, VerificationResult
from sova_security.domain.governance import HoldRelease
from sova_security.domain.signed_evidence import EvidenceEnvelope, VerifierTrust

VERIFIER_VERSION = "sova.security.hold-release-approval.v1"


def hold_release_record(request, *, evidence_id):
    if not isinstance(request, HoldRelease):
        raise ContractError("Typed hold release approval required")
    fingerprint = hashlib.sha256(
        canonical_json(request.document, limit=16384).encode()
    ).hexdigest()
    return EvidenceRecord(
        evidence_id,
        "security-release-approval:" + request.hold_id,
        request.scope,
        request.revisions,
        VERIFIER_VERSION,
        request.approved_at,
        request.valid_until,
        VerificationResult.PASS,
        "hold-release-approval:" + fingerprint,
        fingerprint,
    )


class HoldReleaseAuthority:
    def __init__(
        self, *, envelope_provider, current_revisions, resolve_trust, authorize, clock
    ):
        self.envelope_provider = envelope_provider
        self.current_revisions = current_revisions
        self.resolve_trust = resolve_trust
        self.authorize = authorize
        self.clock = clock
        self.verifier = Ed25519EvidenceVerifier(resolve_trust)

    def __call__(self, request):
        if not isinstance(request, HoldRelease):
            raise ContractError("Typed hold release approval required")
        started = utc(self.clock())
        require_accept(
            self.authorize,
            request.approved_by,
            request.scope,
            "security:release-approve",
        )
        if self.current_revisions(request.scope) != request.revisions:
            raise ContractError("Hold release approval revision changed")
        envelope = self.envelope_provider(request)
        if (
            not isinstance(envelope, EvidenceEnvelope)
            or envelope.issuer_id != request.approved_by
        ):
            raise ContractError("Registered security approver signature required")
        record = hold_release_record(request, evidence_id=envelope.evidence.evidence_id)
        trust = self.resolve_trust(envelope.issuer_id, envelope.key_id)
        if not isinstance(trust, VerifierTrust):
            raise ContractError("Current hold release approver key required")
        self.verifier.verify(envelope, expected_record=record, now=self.clock())
        require_accept(
            self.authorize,
            request.approved_by,
            request.scope,
            "security:release-approve",
        )
        self.verifier.verify(envelope, expected_record=record, now=self.clock())
        if (
            self.resolve_trust(envelope.issuer_id, envelope.key_id) != trust
            or self.current_revisions(request.scope) != request.revisions
            or self.envelope_provider(request) != envelope
        ):
            raise ContractError("Hold release approval authority changed")
        final = utc(self.clock())
        if (
            not request.approved_at
            <= started
            <= final
            < min(request.valid_until, trust.valid_until)
        ):
            raise ContractError("Hold release approval expired before return")
