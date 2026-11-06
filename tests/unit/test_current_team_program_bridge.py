"""Current platform snapshot -> existing importer -> signed program producer.

The upstream example is synthetic. Schema and actual Ed25519 checks are real;
this does not claim a cloud denial test was performed by the test suite.
"""

from dataclasses import replace
from pathlib import Path
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from program_support import program_bundle
from team_controls_support import team_control_bundle
from sova_security.adapters.ed25519_evidence import Ed25519EvidenceSigner
from sova_security.adapters.program_evidence import SignedProgramEvidence
from sova_security.adapters.team_control_results import import_control_run
from sova_security.contracts.commands import ContractError
from sova_security.contracts.evidence import VerificationResult as R
from sova_security.domain.program_evidence import ProgramEvidenceRoute, ProgramSource
from sova_security.domain.security_program import ProgramPhase, review_program
from sova_security.domain.signed_evidence import VerifierTrust
from sova_security.domain.team_controls import CURRENT_SCHEMA_DIGEST


@pytest.mark.parametrize("case", ["pass", "unknown", "fail"])
def test_current_team_identity_result_preserves_outcome_in_program(case):
    _, profile, now = team_control_bundle()
    profile = replace(profile, schema_digest=CURRENT_SCHEMA_DIGEST)
    body = json.loads(
        (
            Path(__file__).parents[1] / "fixtures/team-control-source-run-20261106.json"
        ).read_bytes()
    )
    row = next(row for row in body["results"] if row["test_id"].startswith("IAM-01."))
    if case == "unknown":
        row.update(
            verdict="UNKNOWN",
            unknown_reason="POSITIVE_CONTROL_FAILED",
            positive_control="fail",
        )
    elif case == "fail":
        row.update(verdict="FAIL", observed="allow")
    imported = import_control_run(
        json.dumps(body).encode(), registration=profile, now=now
    )
    record = next(
        record
        for record in imported.evidence
        if record.obligation_id == "team-control:" + row["test_id"]
    )
    program, _ = program_bundle(profile.scope, now)
    program = replace(
        program,
        bindings=tuple(
            replace(binding, revisions=profile.revisions)
            for binding in program.bindings
        ),
    )
    signer = Ed25519EvidenceSigner(
        Ed25519PrivateKey.generate(),
        issuer_id="registered-team-verifier",
        key_id="test-key",
    )
    route = ProgramEvidenceRoute(
        program.fingerprint, "identity-boundary", (ProgramSource(signer.issuer_id, record),)
    )
    envelope = signer.sign(record, issued_at=now)
    trust = VerifierTrust(
        signer.issuer_id,
        signer.key_id,
        signer.public_key_hex,
        (profile.scope,),
        (record.verifier_version,),
        profile.observed_at,
        profile.valid_until,
    )
    authority = SignedProgramEvidence(
        current_program=lambda: program,
        routes_for=lambda _: (route,),
        authenticate_route=lambda _: True,
        envelope_for=lambda _: envelope,
        resolve_trust=lambda *_: trust,
        clock=lambda: now,
    )
    evidence = authority.evidence_for(program, ProgramPhase.PREFLIGHT)
    assert len(evidence) == 1 and evidence[0].result == R(case)
    assert authority.authenticate_evidence(evidence[0]) == evidence[0]
    assert not review_program(program, ProgramPhase.PREFLIGHT, evidence, now=now).passed


def test_current_team_schema_rejects_mismatched_test_control_and_gate_documents():
    body, profile, now = team_control_bundle()
    profile = replace(profile, schema_digest=CURRENT_SCHEMA_DIGEST)
    body["results"][0]["control_id"] = "AUD-01"
    with pytest.raises(ContractError, match="Schema"):
        import_control_run(json.dumps(body).encode(), registration=profile, now=now)
    with pytest.raises(ContractError, match="Only raw control runs"):
        import_control_run(
            b'{"kind":"gate_comparison","decision":"PASS"}',
            registration=profile,
            now=now,
        )
