"""Real pinned T10/T19 modules + SQLite admission; synthetic measurement/identity.

Set SOVA_PLATFORM_SOURCE to a clean, detached checkout of PLATFORM_BASELINE.
These optional cross-repository checks never modify the platform checkout.
"""

from dataclasses import replace
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from program_support import program_bundle
from sova_security.adapters.modernization_codec import decode, encode
from sova_security.adapters.platform_review import PLATFORM_BASELINE, T10ProgramAuthority, t10_host_binding
from sova_security.adapters.remote_review import RemoteReviewClient
from sova_security.adapters.review_https import BearerCredential
from sova_security.application.review_service import SecurityReviewEndpoint
from sova_security.application.security_program import SecurityProgramService
from sova_security.contracts.commands import ResourceScope
from sova_security.domain.review_service import ReviewPrincipal, ReviewRegistration
from sova_security.domain.security_program import ProgramPhase


@pytest.fixture
def platform_admission(tmp_path, request):
    location = os.environ.get("SOVA_PLATFORM_SOURCE")
    if not location:
        pytest.skip("Explicit pinned SOVA_PLATFORM_SOURCE required for platform interoperability")
    root = Path(location).resolve()
    git = ["git", "-c", f"safe.directory={root.as_posix()}", "-C", str(root)]
    assert subprocess.check_output(git + ["rev-parse", "HEAD"], text=True).strip() == PLATFORM_BASELINE
    assert not subprocess.check_output(git + ["status", "--porcelain"])
    paths = [root / "services/control-gate/src", root / "services/platform-events/src", root / "services/control-gate/tests"]
    old_path = list(sys.path)
    sys.path[:0] = [str(p) for p in paths]

    def module(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        value = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(value)
        return value

    try:
        fixtures = module("pinned_gate_fixtures", paths[2] / "conftest.py")
        readiness = module("pinned_readiness_fixtures", paths[2] / "test_readiness.py")
        admission = module("pinned_admission_fixtures", paths[2] / "test_t10_interop.py")
        contract = fixtures.contract.__wrapped__()
        bundle = fixtures.bundle.__wrapped__(contract)
        service = fixtures.service.__wrapped__(contract, bundle)
        ready = readiness.ready.__wrapped__(service)
        parameter = SimpleNamespace(param="sqlite", getfixturevalue=lambda name: ready if name == "ready" else None)
        value = admission.admission.__wrapped__(parameter, tmp_path, "context", request.param)
        yield value
    finally:
        sys.path[:] = old_path


def attach(fixture):
    f = fixture
    ctx, now = f.state["context"], f.state["now"]
    scope = ResourceScope(ctx.tenant_id, ctx.app, ctx.target_environment_id, "registered-workload")
    program, records = program_bundle(scope, now, subject=ctx.plan_digest)
    source = replace(scope, environment_id=ctx.source_environment_id)
    program = replace(program, source=source, bindings=tuple(replace(b, obligation=replace(b.obligation, scope=source))
                      if b.obligation.scope == program.source else b for b in program.bindings))
    records = tuple(replace(r, scope=source) if r.scope.environment_id == "owned-source" else r for r in records)
    with f.store._transaction(write=True, plan_id=f.plan.plan_id) as connection:
        row = dict(connection.execute("SELECT * FROM plans WHERE plan_id=?", (f.plan.plan_id,)).fetchone())
        f.adapter(connection, f.principal, row, now=now.isoformat(), approved_by="operator", approval_id="test")
        session = f.loader(connection, f.principal, row)
        host = t10_host_binding(program, session, row)
    registration = ReviewRegistration(program, host, ProgramPhase.PREFLIGHT, now, program.valid_until)
    actor = ReviewPrincipal("service-worker", ctx.tenant_id, (source, scope), ("enforce", "shadow"),
                            now, program.valid_until, "9" * 64)
    state = {"registration": registration, "host_registration": registration, "evidence": records, "hook": lambda: None, "requests": 0}
    service = SecurityProgramService(program_for=lambda *_: program, evidence_for=lambda *_: state["evidence"],
        authenticate_program=lambda value: value == program, authenticate_evidence=lambda value: value in state["evidence"],
        authorize=lambda *_: True, require_no_holds=lambda *_: True, clock=lambda: f.state["now"])
    endpoint = SecurityReviewEndpoint(authenticate=lambda _: actor, registration_for=lambda *_: state["registration"],
        service_for=lambda *_: service, audit=lambda _: True, clock=lambda: f.state["now"])

    def post(_path, raw, credential):
        state["requests"] += 1
        result = encode(endpoint.review(credential.token, decode(raw))).encode()
        state["hook"]()
        return result

    client = RemoteReviewClient(transport=SimpleNamespace(post=post),
        credential_for=lambda: BearerCredential("synthetic-service-token", actor.valid_until),
        current_registration=lambda *_: state["registration"], subject_id=actor.subject_id, clock=lambda: f.state["now"])
    f.service.authority = T10ProgramAuthority(upstream=f.adapter, load_session=f.loader, client=client,
                                            load_registration=lambda connection, *_: state["host_registration"] if connection.in_transaction else None,
                                            scope=scope, clock=lambda: f.state["now"])
    return state, client


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
