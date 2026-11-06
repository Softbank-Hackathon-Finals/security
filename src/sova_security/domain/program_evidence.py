"""Host-registered mappings from existing verifier records to program checks.

These documents describe provenance; neither decoding nor projecting them grants
trust. SignedProgramEvidence authenticates the original envelopes on every use.
"""

from dataclasses import dataclass

from sova_security.contracts.commands import ContractError, digest, identifier, utc
from sova_security.contracts.evidence import EvidenceRecord, VerificationResult as R
from sova_security.domain.assessment import Document, bounded_tuple
from sova_security.domain.security_program import SecurityProgram, CHECKS
from sova_security.domain.signed_evidence import EvidenceEnvelope


@dataclass(frozen=True, slots=True)
class ProgramSource(Document):
    issuer_id: str
    record: EvidenceRecord

    def __post_init__(self):
        identifier(self.issuer_id)
        if not isinstance(self.record, EvidenceRecord):
            raise ContractError("Exact typed producer evidence required")
        if self.record.obligation_id.startswith("security-program:"):
            raise ContractError("Program projections cannot be their own source")


@dataclass(frozen=True, slots=True)
class ProgramEvidenceRoute(Document):
    program_digest: str
    check_id: str
    sources: tuple[ProgramSource, ...]

    def __post_init__(self):
        digest(self.program_digest)
        if self.check_id not in {check.check_id for check in CHECKS}:
            raise ContractError("Known program check required")
        bounded_tuple(self.sources, ProgramSource, limit=16, nonempty=True)
        if len({s.record.evidence_id for s in self.sources}) != len(self.sources):
            raise ContractError("Distinct producer evidence identities required")
        object.__setattr__(
            self,
            "sources",
            tuple(sorted(self.sources, key=lambda s: s.record.evidence_id)),
        )

    def binding_for(self, program):
        if (
            not isinstance(program, SecurityProgram)
            or self.program_digest != program.fingerprint
        ):
            raise ContractError("Evidence route belongs to another registered program")
        binding = next(
            (b for b in program.bindings if b.check_id == self.check_id), None
        )
        if binding is None or any(
            s.record.scope != binding.obligation.scope
            or s.record.revisions != binding.revisions
            for s in self.sources
        ):
            raise ContractError("Producer evidence crosses program scope or revisions")
        return binding


@dataclass(frozen=True, slots=True)
class ProgramEvidenceProjection(Document):
    program_digest: str
    route_digest: str
    check_id: str
    source_envelope_digests: tuple[str, ...]

    def __post_init__(self):
        digest(self.program_digest)
        digest(self.route_digest)
        if self.check_id not in {check.check_id for check in CHECKS}:
            raise ContractError("Known projection check required")
        bounded_tuple(self.source_envelope_digests, str, limit=16, nonempty=True)
        for value in self.source_envelope_digests:
            digest(value)
        if len(set(self.source_envelope_digests)) != len(self.source_envelope_digests):
            raise ContractError("Duplicate projection source")


def project_evidence(program, route, envelopes, *, now):
    """Pure projection, not signature verification or an execution permission."""
    if not isinstance(route, ProgramEvidenceRoute):
        raise ContractError("Typed registered route required")
    binding = route.binding_for(program)
    bounded_tuple(envelopes, EvidenceEnvelope, limit=16, nonempty=True)
    if len(envelopes) != len(route.sources):
        raise ContractError("Every registered producer envelope is required")
    now = utc(now)
    if not program.issued_at <= now < program.valid_until:
        raise ContractError("Current program required for projection")
    for source, envelope in zip(route.sources, envelopes, strict=True):
        if envelope.issuer_id != source.issuer_id or envelope.evidence != source.record:
            raise ContractError(
                "Producer envelope differs from registered exact record"
            )
        if (
            not source.record.observed_at
            <= envelope.issued_at
            <= now
            < source.record.valid_until
        ):
            raise ContractError("Current producer evidence required")
    results = {source.record.result for source in route.sources}
    result = (
        R.FAIL if R.FAIL in results else R.PASS if results == {R.PASS} else R.UNKNOWN
    )
    projection = ProgramEvidenceProjection(
        program.fingerprint,
        route.fingerprint,
        route.check_id,
        tuple(envelope.fingerprint for envelope in envelopes),
    )
    record = EvidenceRecord(
        "program-proof:" + projection.fingerprint,
        binding.obligation.obligation_id,
        binding.obligation.scope,
        binding.revisions,
        binding.obligation.verifier_version,
        # Keep the oldest constituent observation: combining a new proof with
        # an old one must not make the old proof pass a postflight time boundary.
        min(s.record.observed_at for s in route.sources),
        min(program.valid_until, *(s.record.valid_until for s in route.sources)),
        result,
        "program-projection:" + projection.fingerprint,
        projection.fingerprint,
    )
    return record, projection
