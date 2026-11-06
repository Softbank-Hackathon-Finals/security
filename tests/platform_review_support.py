"""Real pinned T10/T19 modules + SQLite admission; synthetic measurement/identity.

Set SOVA_PLATFORM_SOURCE to a clean, detached checkout of PLATFORM_BASELINE.
These optional cross-repository checks never modify the platform checkout.
"""

from dataclasses import replace
from datetime import UTC, datetime
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from program_support import program_bundle
from sova_security.adapters.modernization_codec import decode, encode
from sova_security.adapters.platform_review import PLATFORM_BASELINES, T10ProgramAuthority, t10_host_binding
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
    baseline = subprocess.check_output(git + ["rev-parse", "HEAD"], text=True).strip()
    assert baseline in PLATFORM_BASELINES
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
        phase = request.param
        if type(phase) is dict:
            phase = phase["gate_phase"]
            # Only synthetic test observations are shifted. No stored production
            # proof is reissued or made fresh by this fixture.
            context, source, target, previous = bundle
            current = datetime.now(UTC)
            delta = current - previous
            def shifted(value):
                if type(value) is dict:
                    return {k: shifted(v) for k, v in value.items()}
                if type(value) is list:
                    return [shifted(v) for v in value]
                if type(value) is str and len(value) > 19 and value[4:5] == "-" and value[10:11] == "T":
                    try:
                        return (datetime.fromisoformat(value.replace("Z", "+00:00")) + delta).isoformat()
                    except ValueError:
                        pass
                return value
            from bravo_gate.models import fingerprint
            source, target = shifted(source), shifted(target)
            context = replace(context, source_digest=fingerprint(source), target_digest=fingerprint(target))
            bundle = context, source, target, current
        service = fixtures.service.__wrapped__(contract, bundle)
        ready = readiness.ready.__wrapped__(service)
        parameter = SimpleNamespace(param="sqlite", getfixturevalue=lambda name: ready if name == "ready" else None)
        value = admission.admission.__wrapped__(parameter, tmp_path, "context", phase)
        value.platform_baseline = baseline
        yield value
    finally:
        sys.path[:] = old_path


def attach(fixture, *, resource_id="registered-workload"):
    f = fixture
    ctx, now = f.state["context"], f.state["now"]
    scope = ResourceScope(ctx.tenant_id, ctx.app, ctx.target_environment_id, resource_id)
    program, records = program_bundle(scope, now, subject=ctx.plan_digest)
    source = replace(scope, environment_id=ctx.source_environment_id)
    program = replace(program, source=source, bindings=tuple(replace(b, obligation=replace(b.obligation, scope=source))
                      if b.obligation.scope == program.source else b for b in program.bindings))
    records = tuple(replace(r, scope=source) if r.scope.environment_id == "owned-source" else r for r in records)
    with f.store._transaction(write=True, plan_id=f.plan.plan_id) as connection:
        row = dict(connection.execute("SELECT * FROM plans WHERE plan_id=?", (f.plan.plan_id,)).fetchone())
        f.adapter(connection, f.principal, row, now=now.isoformat(), approved_by="operator", approval_id="test")
        session = f.loader(connection, f.principal, row)
        host = t10_host_binding(program, session, row, baseline_sha=f.platform_baseline)
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
                                            baseline_sha=f.platform_baseline,
                                            load_registration=lambda connection, *_: state["host_registration"] if connection.in_transaction else None,
                                            scope=scope, clock=lambda: f.state["now"])
    return state, client

