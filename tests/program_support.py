"""Synthetic controls: cryptographic validity is not real cloud qualification."""

from dataclasses import replace
from datetime import timedelta

from sova_security.contracts.evidence import (
    EvidenceRecord,
    Gate,
    RevisionSet,
    VerificationObligation,
    VerificationResult,
)
from sova_security.domain.security_program import (
    ProgramBinding,
    ProgramKind,
    ProgramPhase,
    SecurityProgram,
    checks_for,
    obligation_id,
)


def program_bundle(scope, now, kind=ProgramKind.MIGRATION, subject="a" * 64):
    source = replace(scope, environment_id="owned-source")
    revisions = RevisionSet("b" * 64, "c" * 64, "d" * 64, "e" * 64)
    bindings = tuple(
        ProgramBinding(
            c.check_id,
            VerificationObligation(
                obligation_id(subject, c.check_id),
                source if c.role == "source" else scope,
                Gate.PREFLIGHT
                if c.phase == ProgramPhase.PREFLIGHT
                else Gate.POSTFLIGHT,
                "test-only:" + c.check_id,
            ),
            revisions,
        )
        for c in checks_for(kind)
    )
    program = SecurityProgram(
        kind, subject, source, scope, bindings, now, now + timedelta(minutes=10)
    )
    evidence = tuple(
        EvidenceRecord(
            "test:" + b.check_id,
            b.obligation.obligation_id,
            b.obligation.scope,
            b.revisions,
            b.obligation.verifier_version,
            now,
            now + timedelta(minutes=5),
            VerificationResult.PASS,
            "synthetic:" + b.check_id,
            "f" * 64,
        )
        for b in program.bindings
    )
    return program, evidence
