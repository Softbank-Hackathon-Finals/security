"""Platform's public-signature ledger keeps current expiry/revocation semantics."""

from dataclasses import replace
from datetime import timedelta

import pytest

from platform_review_support import platform_admission as pinned_admission

platform_admission = pinned_admission


@pytest.mark.parametrize("platform_admission", ["initial", "post_apply"], indirect=True)
@pytest.mark.parametrize("fault", ["revocation", "expiry"])
def test_published_context_signature_is_current_across_plan_views(platform_admission, fault):
    f = platform_admission
    if f.platform_baseline != "7edab5312f965bd683a7738e74d49b883190e8da":
        pytest.skip("Public signature ledger did not exist in this historical baseline")
    from bravo_platform_events.gate_records import GateRecords
    from bravo_platform_events.plan_api import Principal
    from bravo_gate.authority_records import PlanAuthorityRecords
    from bravo_gate.contract import GateError, canonical
    from bravo_gate.signatures import AuthorityEnvelope, AuthorityKey, DOMAIN
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    ctx, now = f.state["context"], f.state["now"]
    manager = Principal("signature-key-manager", ctx.tenant_id)
    def authorize(_connection, actor, plan, action):
        allowed = {"gate:manage-provenance"} if actor == manager else {
            "gate:read", "gate:record", "gate:bind", "gate:publish-provenance"} if actor == f.principal else set()
        return actor.tenant_id == ctx.tenant_id and plan["plan_id"] == f.plan.plan_id and action in allowed
    records = GateRecords(f.store, authorize=authorize)
    registry = PlanAuthorityRecords(records, clock=lambda: f.state["now"])
    for side in ("source", "target"):
        records.record_run(f.principal, f.plan.plan_id, side, f.state["runs"][side])
    records.bind(f.principal, f.plan.plan_id, "context", ctx, expected_revision=0)
    private = Ed25519PrivateKey.generate()
    key = AuthorityKey(private.public_key().public_bytes_raw().hex(), (ctx.tenant_id,), ("context",),
        (now - timedelta(seconds=1)).isoformat(), (now + timedelta(minutes=2)).isoformat(), False)
    registry.enroll(manager, f.plan.plan_id, issuer_id="context-producer", key_id="owned-key",
        producer_subject_id=f.principal.subject_id, key=key, expected_revision=0)
    expiry = now + timedelta(seconds=20)
    envelope = AuthorityEnvelope("context-producer", "owned-key", "context", ctx.fingerprint,
        ctx.fingerprint, now.isoformat(), expiry.isoformat(), "0" * 128)
    envelope = replace(envelope, signature_hex=private.sign(DOMAIN + canonical(envelope.payload)).hex())
    before = f.store.snapshot(f.plan.plan_id)
    receipt = registry.publish(f.principal, f.plan.plan_id, envelope)
    assert registry.publish(f.principal, f.plan.plan_id, envelope) == receipt
    assert f.store.snapshot(f.plan.plan_id) == before

    def verify():
        # Reconstruct callbacks and reread the durable record, never use a saved PASS.
        current = PlanAuthorityRecords(records, clock=lambda: f.state["now"])
        with f.store._transaction(write=True, plan_id=f.plan.plan_id) as connection:
            plan = dict(connection.execute("SELECT * FROM plans WHERE plan_id=?", (f.plan.plan_id,)).fetchone())
            view = records.view(connection, f.principal, plan)
            return current.authority(view).verify(ctx, ctx.fingerprint, "context")
    assert verify().valid_until == expiry
    if fault == "revocation":
        registry.revoke(manager, f.plan.plan_id, issuer_id="context-producer", key_id="owned-key", expected_revision=1)
    else:
        f.state["now"] = expiry + timedelta(microseconds=1)
    with pytest.raises(GateError):
        verify()
    assert f.store.snapshot(f.plan.plan_id) == before
    assert not f.requests
