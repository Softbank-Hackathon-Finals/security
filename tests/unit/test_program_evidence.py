"""Real signatures over synthetic producer facts, no cloud qualification."""

from dataclasses import replace
from datetime import timedelta
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from program_support import program_bundle
from sova_security.adapters.ed25519_evidence import Ed25519EvidenceSigner
from sova_security.adapters.modernization_codec import decode, encode
from sova_security.adapters.program_evidence import SignedProgramEvidence
from sova_security.application.security_program import SecurityProgramService
from sova_security.contracts.commands import ContractError
from sova_security.contracts.evidence import VerificationResult as R
from sova_security.domain.program_evidence import ProgramEvidenceRoute, ProgramSource
from sova_security.domain.security_program import ProgramPhase, review_program
from sova_security.domain.signed_evidence import VerifierTrust


@pytest.fixture
def producers(scope, now):
    program, records = program_bundle(scope, now)
    signer = Ed25519EvidenceSigner(
        Ed25519PrivateKey.generate(), issuer_id="owned-producer", key_id="key"
    )
    original = tuple(
        replace(
            record,
            obligation_id="producer:" + binding.check_id,
            verifier_version="producer-method:v1",
        )
        for binding, record in zip(program.bindings, records, strict=True)
    )
    routes = tuple(
        ProgramEvidenceRoute(
            program.fingerprint,
            binding.check_id,
            (ProgramSource(signer.issuer_id, record),),
        )
        for binding, record in zip(program.bindings, original, strict=True)
    )
    trust = VerifierTrust(
        signer.issuer_id,
        signer.key_id,
        signer.public_key_hex,
        (program.source, program.target),
        ("producer-method:v1",),
        now,
        program.valid_until,
    )
    state = {
        "program": program,
        "routes": routes,
        "trust": trust,
        "envelopes": {r.evidence_id: signer.sign(r, issued_at=now) for r in original},
        "at": now,
        "route_trusted": True,
        "on_lookup": lambda: None,
    }

    def lookup(source):
        result = state["envelopes"].get(source.record.evidence_id)
        state["on_lookup"]()
        return result

    authority = SignedProgramEvidence(
        current_program=lambda: state["program"],
        routes_for=lambda _: state["routes"],
        authenticate_route=lambda _: state["route_trusted"],
        envelope_for=lookup,
        resolve_trust=lambda *_: state["trust"],
        clock=lambda: state["at"],
    )
    return authority, state, signer


@pytest.mark.parametrize("batch", [False, True])
def test_original_signatures_drive_existing_program_service(producers, scope, batch):
    authority, state, _ = producers
    service = SecurityProgramService(
        program_for=lambda *_: state["program"],
        evidence_for=authority.evidence_for,
        authenticate_program=lambda _: True,
        authenticate_evidence=authority.authenticate_evidence,
        authorize=lambda *_: True,
        require_no_holds=lambda _: True,
        clock=lambda: state["at"],
        authenticate_evidence_batch=authority.authenticate_batch if batch else None,
    )
    for phase in ProgramPhase:
        report = service.review(
            "operator",
            scope=scope,
            subject_digest=state["program"].subject_digest,
            phase=phase,
        )
        assert report.passed
    proof = authority.evidence_for(state["program"], ProgramPhase.PREFLIGHT)[0]
    state["trust"] = replace(state["trust"], revoked=True)
    with pytest.raises(ContractError):
        authority.authenticate_evidence(proof)


@pytest.mark.parametrize("fault", ["missing", "tampered", "revoked", "changes-during-read"])
def test_batch_authentication_rechecks_exact_original_collection(producers, fault):
    authority, state, _ = producers
    program, phase = state["program"], ProgramPhase.PREFLIGHT
    records = authority.evidence_for(program, phase)
    assert authority.authenticate_batch((program, phase, records)) is True
    if fault == "missing":
        records = records[1:]
    elif fault == "tampered":
        records = (replace(records[0], artifact_digest="0" * 64),) + records[1:]
    elif fault == "revoked":
        state["trust"] = replace(state["trust"], revoked=True)
    else:
        state["on_lookup"] = lambda: state.update(trust=replace(state["trust"], revoked=True))
    with pytest.raises(ContractError):
        authority.authenticate_batch((program, phase, records))


def test_no_routes_or_missing_originals_remain_unknown(producers):
    authority, state, _ = producers
    program = state["program"]
    state["envelopes"].clear()
    assert authority.evidence_for(program, ProgramPhase.PREFLIGHT) == ()
    state["routes"] = ()
    assert authority.evidence_for(program, ProgramPhase.PREFLIGHT) == ()
    assert not review_program(
        program, ProgramPhase.PREFLIGHT, (), now=state["at"]
    ).passed


@pytest.mark.parametrize(
    "outcome,expected",
    [
        (R.PASS, R.PASS),
        (R.FAIL, R.FAIL),
        (R.UNKNOWN, R.UNKNOWN),
        (R.NOT_APPLICABLE, R.UNKNOWN),
    ],
)
def test_every_original_must_pass_and_waivers_cannot_open_minimum_control(
    producers, outcome, expected
):
    authority, state, signer = producers
    route = next(r for r in state["routes"] if r.check_id == "identity-boundary")
    first = route.sources[0].record
    second = replace(
        first,
        evidence_id="additional-identity-control",
        obligation_id="producer:second",
        result=outcome,
        justification="test waiver" if outcome == R.NOT_APPLICABLE else None,
        approved_by="test reviewer" if outcome == R.NOT_APPLICABLE else None,
    )
    changed = replace(
        route, sources=route.sources + (ProgramSource(signer.issuer_id, second),)
    )
    state["routes"] = tuple(changed if r == route else r for r in state["routes"])
    state["envelopes"][second.evidence_id] = signer.sign(second, issued_at=state["at"])
    records = authority.evidence_for(state["program"], ProgramPhase.PREFLIGHT)
    row = next(r for r in records if r.obligation_id.endswith(":identity-boundary"))
    assert row.result == expected
    assert authority.authenticate_evidence(row) == row


@pytest.mark.parametrize(
    "case",
    [
        "signature",
        "issuer",
        "record",
        "expired",
        "route-revoked",
        "other-program",
        "scope",
        "revision",
        "duplicate-route",
        "input-changes",
        "route-changes",
        "clock-backwards",
    ],
)
def test_invalid_or_changing_producer_authority_is_rejected(producers, case):
    authority, state, signer = producers
    program = state["program"]
    route = next(r for r in state["routes"] if r.check_id == "identity-boundary")
    source = route.sources[0]
    key = source.record.evidence_id
    if case == "signature":
        state["envelopes"][key] = replace(
            state["envelopes"][key], signature_hex="0" * 128
        )
    elif case == "issuer":
        state["envelopes"][key] = replace(
            state["envelopes"][key], issuer_id="another-producer"
        )
    elif case == "record":
        altered = replace(source.record, artifact_digest="0" * 64)
        state["envelopes"][key] = signer.sign(altered, issued_at=state["at"])
    elif case == "expired":
        state["at"] = source.record.valid_until
    elif case == "route-revoked":
        state["route_trusted"] = False
    elif case in {"other-program", "scope", "revision"}:
        if case == "other-program":
            changed = replace(route, program_digest="0" * 64)
        else:
            record = replace(
                source.record,
                **(
                    {"scope": replace(source.record.scope, tenant_id="other")}
                    if case == "scope"
                    else {
                        "revisions": replace(
                            source.record.revisions, environment="0" * 64
                        )
                    }
                ),
            )
            changed = replace(route, sources=(replace(source, record=record),))
        state["routes"] = tuple(changed if r == route else r for r in state["routes"])
    elif case == "duplicate-route":
        state["routes"] += (route,)
    elif case == "input-changes":
        state["on_lookup"] = lambda: state["envelopes"].clear()
    elif case == "route-changes":
        state["on_lookup"] = lambda: state.update(routes=())
    else:
        state["on_lookup"] = lambda: state.update(at=state["at"] - timedelta(seconds=1))
    with pytest.raises(ContractError):
        authority.evidence_for(program, ProgramPhase.PREFLIGHT)


def test_projection_cannot_be_self_attested_rebound_or_freshened(producers):
    authority, state, _ = producers
    program = state["program"]
    record = authority.evidence_for(program, ProgramPhase.PREFLIGHT)[0]
    for altered in (
        replace(record, artifact_digest="0" * 64),
        replace(record, valid_until=record.valid_until + timedelta(seconds=1)),
        replace(record, observed_at=record.observed_at + timedelta(seconds=1)),
    ):
        with pytest.raises(ContractError):
            authority.authenticate_evidence(altered)
    with pytest.raises(ContractError):
        ProgramSource("recursive", record)
    state["at"] += timedelta(seconds=20)
    assert authority.evidence_for(program, ProgramPhase.PREFLIGHT)[0] == record


def test_routes_and_provenance_have_strict_portable_contracts(producers):
    authority, state, _ = producers
    route = state["routes"][0]
    assert decode(encode(route).encode()) == route
    for projection in authority.projections_for(
        state["program"], ProgramPhase.PREFLIGHT
    ):
        assert decode(encode(projection).encode()) == projection
    value = json.loads(encode(route))
    value["value"]["sources"][0]["record"]["result"] = True
    with pytest.raises(ContractError):
        decode(json.dumps(value).encode())
    with pytest.raises(ContractError):
        replace(route, sources=())


def test_new_constituent_cannot_freshen_old_postflight_evidence(producers):
    authority, state, signer = producers
    program = state["program"]
    route = next(r for r in state["routes"] if r.check_id == "runtime-verification")
    old = route.sources[0].record
    state["at"] += timedelta(seconds=30)
    fresh = replace(
        old,
        evidence_id="new-functional-probe",
        obligation_id="producer:functional",
        observed_at=state["at"],
    )
    changed = replace(
        route, sources=route.sources + (ProgramSource(signer.issuer_id, fresh),)
    )
    state["routes"] = tuple(changed if r == route else r for r in state["routes"])
    state["envelopes"][fresh.evidence_id] = signer.sign(fresh, issued_at=state["at"])
    records = authority.evidence_for(program, ProgramPhase.POSTFLIGHT)
    review = review_program(
        program,
        ProgramPhase.POSTFLIGHT,
        records,
        now=state["at"],
        not_before=state["at"] - timedelta(seconds=1),
    )
    row = next(r for r in review.results if r.check_id == route.check_id)
    assert row.result == R.UNKNOWN
    assert row.reason == "observation_precedes_operation"
