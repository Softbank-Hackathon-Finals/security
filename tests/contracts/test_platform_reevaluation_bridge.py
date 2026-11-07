"""A fresh T19 re-evaluation never substitutes for the additional current review."""

from datetime import timedelta
import json

import pytest

from platform_review_support import attach, platform_admission as pinned_admission

platform_admission = pinned_admission
BASELINES = {"0795f65e24f58e43545b16b97757efcc0923fd4a", "445848d2ed9878e31eb6f5aabad0575c61739b47", "c364e6284d2e635ff86001e2feac88560ed23ebc"}


@pytest.mark.parametrize("platform_admission", ["initial", "post_apply"], indirect=True)
@pytest.mark.parametrize("fault", [None, "remote-evidence", "fresh-block", "fresh-binding"])
def test_stored_gate_age_and_current_remote_review_remain_separate(platform_admission, monkeypatch, fault):
    f = platform_admission
    if f.platform_baseline not in BASELINES:
        pytest.skip("Historical platform predates dispatch-time re-evaluation")
    from bravo_gate.contract import canonical
    from bravo_platform_events.store import EventError

    # Synthetic stored report age only. Current source evidence is unchanged;
    # this does not renew real observations or production signatures.
    stored = json.loads(canonical(f.gate.evaluate("operator", "context")))
    stored["evaluated_at"] = (f.state["now"] - timedelta(hours=2)).isoformat()
    raw = canonical(stored).decode()
    f.report_revision += 1
    key = f"fixture-gate-{f.report_revision:08d}"
    with f.store._transaction(write=True, plan_id=f.plan.plan_id) as connection:
        connection.execute("INSERT INTO plan_commands VALUES (?, ?, '{}', ?)", (f.plan.plan_id, key, raw))
    state, _ = attach(f)
    original = f.gate.evaluate
    if fault == "remote-evidence":
        state["evidence"] = ()
    elif fault == "fresh-block":
        monkeypatch.setattr(f.gate, "evaluate", lambda *a, **kw: original(*a, **kw) | {"decision": "BLOCK"})
    elif fault == "fresh-binding":
        monkeypatch.setattr(f.gate, "evaluate", lambda *a, **kw: original(*a, **kw) | {"readiness_binding_digest": "e" * 64})

    if fault:
        with pytest.raises(EventError):
            f.approve()
        assert not f.requests
        assert state["requests"] == (1 if fault == "remote-evidence" else 0)
    else:
        approved = f.approve()
        f.submit(approved)
        f.submit(approved)
        assert [method for method, _ in f.requests] == ["POST", "GET"]
        with f.store._transaction() as connection:
            assert connection.execute("SELECT receipt_json FROM plan_commands WHERE plan_id=? AND command_key=?",
                                      (f.plan.plan_id, key)).fetchone()["receipt_json"] == raw
            assert connection.execute("SELECT count(*) AS n FROM plan_commands WHERE plan_id=? AND command_key LIKE ?",
                                      (f.plan.plan_id, "gate-cutover-reevaluation-%")).fetchone()["n"] >= 1
