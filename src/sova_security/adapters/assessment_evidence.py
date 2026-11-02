"""Concrete signing boundary for registered assessment/rehearsal inputs.

Reuses existing Ed25519 envelopes and verifier trust. It authenticates a typed
document's provenance, not the truth/completeness of arbitrary collector claims.
"""

from types import MappingProxyType

from sova_security.adapters.ed25519_evidence import Ed25519EvidenceVerifier
from sova_security.adapters.modernization_codec import kind_of
from sova_security.contracts.authority import require_accept
from sova_security.contracts.commands import ContractError, identifier, utc
from sova_security.contracts.evidence import (
    EvidenceRecord,
    RevisionSet,
    VerificationResult,
)
from sova_security.domain.assessment import (
    AssetInventory,
    VulnerabilityScan,
    ExposureObservation,
    RiskPolicy,
    Assessment,
)
from sova_security.domain.remediation import RehearsalRequest
from sova_security.domain.signed_evidence import EvidenceEnvelope, VerifierTrust

INPUT_CLOCKS = MappingProxyType(
    {
        AssetInventory: "observed_at",
        VulnerabilityScan: "observed_at",
        ExposureObservation: "observed_at",
        RiskPolicy: "issued_at",
        Assessment: "assessed_at",
        RehearsalRequest: "created_at",
    }
)


def assessment_input_record(value, *, revisions, evidence_id):
    timestamp = INPUT_CLOCKS.get(type(value))
    if timestamp is None or not isinstance(revisions, RevisionSet):
        raise ContractError(
            "Supported typed assessment input and current revisions required"
        )
    kind = kind_of(value)
    scope = value.proposal.scope if isinstance(value, RehearsalRequest) else value.scope
    return EvidenceRecord(
        evidence_id,
        "assessment-input:" + kind,
        scope,
        revisions,
        "sova.security.assessment-input." + kind,
        getattr(value, timestamp),
        value.valid_until,
        VerificationResult.PASS,
        "assessment-input:" + kind + ":" + value.fingerprint,
        value.fingerprint,
    )


class AssessmentInputAuthority:
    def __init__(
        self,
        *,
        envelope_provider,
        current_revisions,
        issuers_for,
        resolve_trust,
        authorize,
        clock,
    ):
        self.envelope_provider = envelope_provider
        self.current_revisions = current_revisions
        self.issuers_for = issuers_for
        self.resolve_trust = resolve_trust
        self.authorize = authorize
        self.clock = clock
        self.verifier = Ed25519EvidenceVerifier(resolve_trust)

    def __call__(self, actor, scope, value):
        identifier(actor)
        started = utc(self.clock())
        if type(value) not in INPUT_CLOCKS:
            raise ContractError("Unsupported signed assessment input kind")
        kind = kind_of(value)
        require_accept(
            self.authorize, actor, scope, "security:authenticate-assessment-input"
        )
        revisions = self.current_revisions(scope)
        issuers = self.issuers_for(scope, kind)
        if (
            type(issuers) is not tuple
            or not 1 <= len(issuers) <= 8
            or len(set(issuers)) != len(issuers)
        ):
            raise ContractError("Bounded registered input issuers required")
        for issuer in issuers:
            identifier(issuer)
        envelope = self.envelope_provider(actor, scope, value)
        if (
            not isinstance(envelope, EvidenceEnvelope)
            or envelope.issuer_id not in issuers
        ):
            raise ContractError(
                "Independently registered assessment input envelope required"
            )
        record = assessment_input_record(
            value, revisions=revisions, evidence_id=envelope.evidence.evidence_id
        )
        if record.scope != scope:
            raise ContractError("Assessment input authentication crosses scope")
        trust = self.resolve_trust(envelope.issuer_id, envelope.key_id)
        if not isinstance(trust, VerifierTrust):
            raise ContractError("Current registered assessment input key required")
        self.verifier.verify(envelope, expected_record=record, now=self.clock())
        require_accept(
            self.authorize, actor, scope, "security:authenticate-assessment-input"
        )
        # A matching document hash cannot resurrect a revoked key, a changed
        # policy/target revision or an issuer removed from this input role.
        self.verifier.verify(envelope, expected_record=record, now=self.clock())
        if (
            self.resolve_trust(envelope.issuer_id, envelope.key_id) != trust
            or self.current_revisions(scope) != revisions
            or self.issuers_for(scope, kind) != issuers
            or self.envelope_provider(actor, scope, value) != envelope
        ):
            raise ContractError(
                "Assessment input authority changed during authentication"
            )
        final = utc(self.clock())
        if not started <= final < min(record.valid_until, trust.valid_until):
            raise ContractError("Assessment input authority expired before return")
        # Raise-on-deny callback convention, accepted by both existing services.
