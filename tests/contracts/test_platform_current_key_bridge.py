"""Reuse platform's plan key ledger; remote PASS cannot revive upstream trust."""

from dataclasses import replace
from datetime import timedelta

import pytest

from platform_review_support import attach, platform_admission as pinned_admission

platform_admission = pinned_admission


@pytest.mark.parametrize("platform_admission", ["initial", "post_apply"], indirect=True)
@pytest.mark.parametrize("revoked", [False, True])
def test_current_plan_key_ledger_remains_required_at_t10_dispatch(platform_admission, revoked):
    f = platform_admission
    if f.platform_baseline not in {"98885a69999398bfe3f49fbc8324a7b19aae3e16", "7edab5312f965bd683a7738e74d49b883190e8da", "42811da4cf19ce941491d4794ab49790881dc409", "0795f65e24f58e43545b16b97757efcc0923fd4a", "445848d2ed9878e31eb6f5aabad0575c61739b47"}:
        pytest.skip("Plan public-key registry did not exist in this historical baseline")
    from bravo_platform_events.gate_records import GateRecords
    from bravo_platform_events.plan_api import Principal
    from bravo_platform_events.store import EventError
    from bravo_gate.contract import canonical
    from bravo_gate.key_records import PlanAuthorityKeys
    from bravo_gate.models import RunSnapshot, VerifiedAuthority, permission_subject
    from bravo_gate.signatures import DOMAIN, AuthorityEnvelope, AuthorityKey, Ed25519Authority
    from bravo_gate.stored import StoredGateServices
    from bravo_gate.t10 import PlanGateSession
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    manager = Principal("independent-key-manager", f.principal.tenant_id)
    ctx, now = f.state["context"], f.state["now"]
    def authorize(_connection, actor, plan, action):
        allowed = {"gate:manage-provenance"} if actor == manager else {
            "gate:read", "gate:record", "gate:bind", "gate:evaluate"} if actor == f.principal else set()
        return actor.tenant_id == ctx.tenant_id and plan["plan_id"] == f.plan.plan_id and action in allowed
    records = GateRecords(f.store, authorize=authorize)
    registry = PlanAuthorityKeys(records, clock=lambda: f.state["now"])
    envelopes = {}

    def sign(purpose, subject):
        private = Ed25519PrivateKey.generate()
        key = AuthorityKey(private.public_key().public_bytes_raw().hex(), (ctx.tenant_id,), (purpose,),
                           (now - timedelta(seconds=1)).isoformat(),
                           (now + timedelta(minutes=2)).isoformat(), False)
        registry.enroll(manager, f.plan.plan_id, issuer_id=purpose, key_id="owned-key",
                        producer_subject_id="independent-producer", key=key, expected_revision=0)
        value = AuthorityEnvelope(purpose, "owned-key", purpose, ctx.fingerprint, subject,
                                  now.isoformat(), (now + timedelta(seconds=25)).isoformat(), "0" * 128)
        envelopes[purpose, subject] = replace(value, signature_hex=private.sign(DOMAIN + canonical(value.payload)).hex())

    for side in ("source", "target"):
        records.record_run(f.principal, f.plan.plan_id, side, f.state["runs"][side])
        sign("run-" + side, f.state["runs"][side].fingerprint)
    records.bind(f.principal, f.plan.plan_id, "context", ctx, expected_revision=0)
    sign("context", ctx.fingerprint)
    sign("readiness-binding", f.data["binding"].fingerprint)
    sign("readiness-snapshot", f.data["snapshot"].fingerprint)

    def authority(view):
        return Ed25519Authority(
            envelope_provider=lambda _context, subject, purpose: envelopes.get((purpose, subject)),
            key_provider=lambda issuer, key_id: registry.read_key(view, issuer, key_id),
            clock=lambda: f.state["now"])
    factory = StoredGateServices(authority_provider=authority,
        authorize=lambda _view, actor, context, action: VerifiedAuthority(context.fingerprint,
            permission_subject(actor, context.fingerprint, action), "permission:" + action,
            now + timedelta(seconds=20)),
        approval_provider=lambda *_: None, binding_provider=lambda *_: f.data["binding"],
        snapshot_provider=lambda *_: f.data["snapshot"], clock=lambda: f.state["now"])
    before = f.store.snapshot(f.plan.plan_id)
    combined = records.evaluate(f.principal, f.plan.plan_id, service_factory=factory)
    assert combined["decision"] == "PASS"
    with f.store._transaction(write=True, plan_id=f.plan.plan_id) as connection:
        plan = dict(connection.execute("SELECT * FROM plans WHERE plan_id=?", (f.plan.plan_id,)).fetchone())
        view = records.view(connection, f.principal, plan)
        report = view.report_provider(f.principal.subject_id, view.context)
    sign("gate-result", report.fingerprint)
    assert f.store.snapshot(f.plan.plan_id) == before

    def load(connection, principal, plan):
        view = records.view(connection, principal, plan)
        return PlanGateSession(factory(view), f.plan.plan_id, view.context_id, view.context,
            RunSnapshot(ctx.gate_id, canonical(combined)), f.data["binding"],
            gate_phase=f.gate_phase, application_id=f.application_id)
    f.loader = load
    state, _client = attach(f)
    approved = f.approve()
    if revoked:
        registry.revoke(manager, f.plan.plan_id, issuer_id="run-target", key_id="owned-key", expected_revision=1)
        review_requests = state["requests"]
        with pytest.raises(EventError):
            f.submit(approved)
        assert not f.requests and state["requests"] == review_requests
        assert f.store.snapshot(f.plan.plan_id)["state"] == "SHIFT"
    else:
        f.submit(approved)
        f.submit(approved)
        assert [method for method, _ in f.requests] == ["POST", "GET"]
