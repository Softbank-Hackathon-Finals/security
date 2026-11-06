"""Real pinned T10/T19 modules and SQLite with synthetic authority/transport."""

from dataclasses import replace
import pytest
from platform_review_support import attach, platform_admission as pinned_admission

platform_admission = pinned_admission


@pytest.mark.parametrize("platform_admission", ["initial", "post_apply"], indirect=True)
def test_real_t10_admission_keeps_single_dispatch_and_unknown_recovery(platform_admission):
    f = platform_admission
    state, _client = attach(f)
    approval = f.approve()
    first = f.submit(approval)
    assert len([r for r in f.requests if r[0] == "POST"]) == 1
    f.submit(approval)
    assert len([r for r in f.requests if r[0] == "POST"]) == 1
    assert state["requests"] >= 2
    assert first is not None


@pytest.mark.parametrize("platform_admission", ["initial", "post_apply"], indirect=True)
@pytest.mark.parametrize("fault", ["missing-proof", "upstream-revoked", "changed-context", "clock-expired", "none-auth", "host-registration-revoked"])
def test_real_platform_rejects_new_faults_without_external_dispatch(platform_admission, fault):
    from bravo_platform_events.store import EventError
    f = platform_admission
    state, _client = attach(f)
    if fault == "missing-proof":
        state["evidence"] = ()
    elif fault == "upstream-revoked":
        state["hook"] = lambda: setattr(f, "upstream_allowed", False)
    elif fault == "changed-context":
        state["hook"] = lambda: setattr(f, "application_id", "changed-application")
    elif fault == "clock-expired":
        from datetime import timedelta
        state["hook"] = lambda: f.state.update(now=f.state["now"] + timedelta(seconds=6))
    elif fault == "host-registration-revoked":
        state["hook"] = lambda: state.update(host_registration=None)
    else:
        f.state["trusted"] = None  # Platform rejects legacy raise-on-deny return convention.
    with pytest.raises(EventError):
        f.approve()
    assert not f.requests
    if fault == "none-auth":
        assert state["requests"] == 0


@pytest.mark.parametrize("platform_admission", ["post_apply"], indirect=True)
def test_profile_version_and_post_apply_identity_preserve_platform_values(platform_admission):
    from bravo_platform_events.store import EventError
    f = platform_admission
    state, client = attach(f)
    binding = state["registration"].host_binding
    assert binding.profile_version == f.state["context"].profile_version == "1"
    assert binding.gate_phase == "post_apply" and binding.application_id == "applied-1"
    state["registration"] = replace(state["registration"], host_binding=replace(binding, application_id="other"))
    with pytest.raises(EventError):
        f.approve()
    assert state["requests"] == 0 and not f.requests
