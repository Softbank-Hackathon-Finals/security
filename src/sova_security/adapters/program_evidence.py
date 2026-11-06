"""Reauthenticate original signed producer records, without a new signing key.

A host supplies current, authenticated routes and original envelope lookups.
Derived records are usable only with this authority; exported JSON is diagnostic.
"""

from sova_security.adapters.ed25519_evidence import Ed25519EvidenceVerifier
from sova_security.application.boundary import require_authentication
from sova_security.contracts.commands import ContractError, utc
from sova_security.contracts.evidence import EvidenceRecord
from sova_security.domain.assessment import bounded_tuple
from sova_security.domain.program_evidence import ProgramEvidenceRoute, project_evidence
from sova_security.domain.security_program import (
    SecurityProgram,
    ProgramPhase,
    checks_for,
)
from sova_security.domain.signed_evidence import EvidenceEnvelope, VerifierTrust


class SignedProgramEvidence:
    def __init__(
        self,
        *,
        current_program,
        routes_for,
        authenticate_route,
        envelope_for,
        resolve_trust,
        clock,
    ):
        self.current_program = current_program
        self.routes_for = routes_for
        self.authenticate_route = authenticate_route
        self.envelope_for = envelope_for
        self.resolve_trust = resolve_trust
        self.clock = clock
        self.verifier = Ed25519EvidenceVerifier(resolve_trust)

    def _collect(self, program, phase, *, check_id=None):
        if not isinstance(program, SecurityProgram) or not isinstance(
            phase, ProgramPhase
        ):
            raise ContractError("Typed current program and phase required")
        if self.current_program() != program:
            raise ContractError("Program registration changed")
        started = utc(self.clock())
        if not program.issued_at <= started < program.valid_until:
            raise ContractError("Current program registration required")
        routes = self.routes_for(program)
        bounded_tuple(routes, ProgramEvidenceRoute, limit=64)
        if len({r.check_id for r in routes}) != len(routes):
            raise ContractError("Duplicate program evidence route")
        selected = {c.check_id for c in checks_for(program.kind) if c.phase == phase}
        snapshots, outputs = [], []
        for route in routes:
            route.binding_for(program)
            if route.check_id not in selected or (
                check_id is not None and route.check_id != check_id
            ):
                continue
            require_authentication(self.authenticate_route, route)
            envelopes, trusts = [], []
            for source in route.sources:
                envelope = self.envelope_for(source)
                if envelope is None:
                    envelopes.append(None)
                    trusts.append(None)
                    continue
                if (
                    not isinstance(envelope, EvidenceEnvelope)
                    or envelope.issuer_id != source.issuer_id
                ):
                    raise ContractError("Registered producer issuer required")
                trust = self.resolve_trust(envelope.issuer_id, envelope.key_id)
                if not isinstance(trust, VerifierTrust):
                    raise ContractError("Current producer trust required")
                self.verifier.verify(
                    envelope, expected_record=source.record, now=self.clock()
                )
                envelopes.append(envelope)
                trusts.append(trust)
            snapshots.append((route, tuple(envelopes), tuple(trusts)))
            if all(envelope is not None for envelope in envelopes):
                outputs.append(
                    project_evidence(program, route, tuple(envelopes), now=self.clock())
                )

        # No cache grants lasting trust. Re-read original records/roles/keys after
        # callbacks, so route removal and producer revocation invalidate projections.
        for route, envelopes, trusts in snapshots:
            require_authentication(self.authenticate_route, route)
            for source, envelope, trust in zip(
                route.sources, envelopes, trusts, strict=True
            ):
                if self.envelope_for(source) != envelope:
                    raise ContractError("Producer evidence changed during projection")
                if envelope is not None:
                    self.verifier.verify(
                        envelope, expected_record=source.record, now=self.clock()
                    )
                    if self.resolve_trust(envelope.issuer_id, envelope.key_id) != trust:
                        raise ContractError("Producer trust changed during projection")
        if self.current_program() != program or self.routes_for(program) != routes:
            raise ContractError("Program or evidence routes changed during projection")
        finished = utc(self.clock())
        if finished < started or finished >= min(
            [program.valid_until] + [r.valid_until for r, _ in outputs]
        ):
            raise ContractError("Program evidence authority expired during projection")
        return tuple(outputs)

    def evidence_for(self, program, phase):
        return tuple(record for record, _ in self._collect(program, phase))

    def projections_for(self, program, phase):
        return tuple(projection for _, projection in self._collect(program, phase))

    def authenticate_evidence(self, record):
        if not isinstance(record, EvidenceRecord):
            raise ContractError("Typed program evidence required")
        program = self.current_program()
        if not isinstance(program, SecurityProgram):
            raise ContractError("Current registered program required")
        binding = next(
            (
                b
                for b in program.bindings
                if b.obligation.obligation_id == record.obligation_id
            ),
            None,
        )
        if binding is None:
            raise ContractError("Evidence belongs to another plan")
        phase = next(
            c.phase for c in checks_for(program.kind) if c.check_id == binding.check_id
        )
        entries = self._collect(program, phase, check_id=binding.check_id)
        if len(entries) != 1 or entries[0][0] != record:
            raise ContractError(
                "Evidence does not match current authenticated producers"
            )
        return record
