from dataclasses import replace
from datetime import timedelta
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from program_support import program_bundle
from sova_security.adapters.ed25519_evidence import (
    Ed25519EvidenceSigner,
    Ed25519EvidenceVerifier,
)
from sova_security.adapters.modernization_codec import decode, encode
from sova_security.application.security_program import SecurityProgramService
from sova_security.contracts.commands import ContractError
from sova_security.contracts.evidence import VerificationResult as R
from sova_security.domain.security_program import (
    CHECKS,
    ProgramInput,
    ProgramKind,
    ProgramPhase,
    review_program,
)
from sova_security.domain.signed_evidence import VerifierTrust


def test_both_documents_ids_are_traced_without_replacing_existing_gate_numbers():
    references = {ref for check in CHECKS for ref in check.references}
    expected = {f"CTRL-{i:02d}" for i in range(1, 10)}
    expected |= {f"POL-{i:02d}" for i in range(1, 13)}
    expected |= {f"SEC-PATCH-{i:02d}" for i in range(1, 11)}
    expected |= {f"SG-{i}" for i in range(1, 4)}
    assert references == expected


@pytest.mark.parametrize("kind", list(ProgramKind))
def test_versioned_interchange_and_stage_specific_requirements(scope, now, kind):
    program, records = program_bundle(scope, now, kind)
    bundle = ProgramInput(program, records)
    assert decode(encode(program).encode()) == program
    assert decode(encode(bundle).encode()) == bundle
    for phase in ProgramPhase:
        report = review_program(program, phase, records, now=now)
        assert report.passed
        assert report.valid_until == now + timedelta(minutes=5)
    preflight_only = tuple(r for r in records if "runtime" not in r.evidence_id)
    assert review_program(
        program, ProgramPhase.PREFLIGHT, preflight_only, now=now
    ).passed
    assert not review_program(
        program, ProgramPhase.POSTFLIGHT, preflight_only, now=now
    ).passed


@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "failed",
        "unknown",
        "expired",
        "future",
        "scope",
        "revision",
        "verifier",
        "ambiguous",
        "waived",
        "other-plan",
    ],
)
def test_invalid_evidence_cannot_open_the_gate(scope, now, case):
    program, records = program_bundle(scope, now)
    selected = next(r for r in records if r.evidence_id == "test:identity-boundary")
    others = tuple(r for r in records if r != selected)
    changed = {
        "failed": {"result": R.FAIL},
        "unknown": {"result": R.UNKNOWN},
        "expired": {"observed_at": now - timedelta(minutes=2), "valid_until": now},
        "future": {"observed_at": now + timedelta(seconds=1)},
        "scope": {"scope": replace(scope, tenant_id="other-tenant")},
        "revision": {"revisions": replace(selected.revisions, policy="0" * 64)},
        "verifier": {"verifier_version": "model-self-report"},
        "waived": {
            "result": R.NOT_APPLICABLE,
            "justification": "agent says safe",
            "approved_by": "claimed-reviewer",
        },
        "other-plan": {
            "obligation_id": selected.obligation_id.replace("a" * 64, "0" * 64)
        },
    }
    if case == "missing":
        records = others
    elif case == "ambiguous":
        records += (replace(selected, evidence_id="second-proof"),)
    else:
        records = others + (replace(selected, **changed[case]),)
    assert not review_program(program, ProgramPhase.PREFLIGHT, records, now=now).passed


def test_registration_cannot_omit_weaken_or_rebind_checks(scope, now):
    program, _ = program_bundle(scope, now)
    first = program.bindings[0]
    for changes in (
        {"bindings": program.bindings[1:]},
        {"bindings": program.bindings + (first,)},
        {"subject_digest": "0" * 64},
        {"catalog_version": "model-policy"},
        {"source": replace(program.source, tenant_id="another")},
        {"source": program.target},
    ):
        with pytest.raises(ContractError):
            replace(program, **changes)
    with pytest.raises(ContractError):
        replace(first, obligation=replace(first.obligation, required=False))
    body = json.loads(encode(program))
    body["value"]["bindings"][0]["obligation"]["required"] = "true"
    with pytest.raises(ContractError):
        decode(json.dumps(body).encode())


@pytest.fixture
def signed_program(scope, now):
    program, records = program_bundle(scope, now)
    signer = Ed25519EvidenceSigner(
        Ed25519PrivateKey.generate(), issuer_id="test-verifier", key_id="test-key"
    )
    trust = VerifierTrust(
        signer.issuer_id,
        signer.key_id,
        signer.public_key_hex,
        (program.source, program.target),
        tuple(r.verifier_version for r in records),
        now,
        program.valid_until,
    )
    state = {
        "program": program,
        "records": records,
        "trust": trust,
        "at": now,
        "authorized": True,
        "hold": False,
        "registered": True,
        "after_auth": lambda: None,
    }
    envelopes = {r.evidence_id: signer.sign(r, issued_at=now) for r in records}
    verifier = Ed25519EvidenceVerifier(lambda *_: state["trust"])

    def authenticate(record):
        verified = verifier.verify(
            envelopes[record.evidence_id], expected_record=record, now=state["at"]
        )
        state["after_auth"]()
        return verified

    service = SecurityProgramService(
        program_for=lambda *_: state["program"],
        evidence_for=lambda *_: state["records"],
        authenticate_program=lambda _: state["registered"],
        authenticate_evidence=authenticate,
        authorize=lambda *_: state["authorized"],
        require_no_holds=lambda _: not state["hold"],
        clock=lambda: state["at"],
    )
    return service, state, envelopes


def test_real_signatures_and_trust_revocation(signed_program, scope):
    service, state, _ = signed_program
    args = dict(
        scope=scope,
        subject_digest=state["program"].subject_digest,
        phase=ProgramPhase.PREFLIGHT,
    )
    assert service.review("operator", **args).passed
    state["trust"] = replace(state["trust"], revoked=True)
    with pytest.raises(ContractError):
        service.review("operator", **args)


def test_source_authorization_precedes_any_producer_lookup(signed_program, scope):
    service, state, _ = signed_program
    calls = []
    service.authorize = lambda actor, current_scope, action: current_scope == scope
    service.evidence_for = lambda *_: calls.append("read-source")
    with pytest.raises(ContractError):
        service.review(
            "target-only-user",
            scope=scope,
            subject_digest=state["program"].subject_digest,
            phase=ProgramPhase.PREFLIGHT,
        )
    assert calls == []


@pytest.mark.parametrize(
    "case",
    [
        "signature",
        "authority",
        "hold",
        "registration",
        "scope",
        "changed",
        "expired",
        "backwards",
        "hold-during-io",
    ],
)
def test_host_service_rechecks_authority_and_current_inputs(
    signed_program, scope, now, case
):
    service, state, envelopes = signed_program
    program = state["program"]
    if case == "signature":
        key = next(iter(envelopes))
        envelopes[key] = replace(envelopes[key], signature_hex="0" * 128)
    if case == "authority":
        state["authorized"] = False
    if case == "hold":
        state["hold"] = True
    if case == "registration":
        state["registered"] = False
    if case == "scope":
        scope = replace(scope, application_id="other-app")
    if case == "changed":
        state["after_auth"] = lambda: state.update(
            program=replace(
                program, valid_until=program.valid_until + timedelta(seconds=1)
            )
        )
    if case == "expired":
        state["after_auth"] = lambda: state.update(at=now + timedelta(minutes=20))
    if case == "backwards":
        state["after_auth"] = lambda: state.update(at=now - timedelta(seconds=1))
    if case == "hold-during-io":
        state["after_auth"] = lambda: state.update(hold=True)
    with pytest.raises(ContractError):
        service.review(
            "operator",
            scope=scope,
            subject_digest=program.subject_digest,
            phase=ProgramPhase.PREFLIGHT,
        )
