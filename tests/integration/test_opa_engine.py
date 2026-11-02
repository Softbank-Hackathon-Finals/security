"""Actual pinned OPA. No networked OPA service, cloud credentials or guest code."""

from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import os
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from opa_support import opa_bundle
from sova_security.adapters.opa_local import PinnedLocalOPA
from sova_security.application.opa_policy import OPAPlanPolicy
from sova_security.contracts.commands import ContractError
from sova_security.contracts.evidence import VerificationResult as R

pytestmark = pytest.mark.policy_engine


@pytest.fixture
def evaluator():
    path = os.environ.get("SOVA_TEST_OPA_PATH")
    if not path:
        pytest.skip("Explicit pinned SOVA_TEST_OPA_PATH required")
    expected = os.environ.get("SOVA_TEST_OPA_SHA256")
    assert expected and Path(path).is_file(), (
        "Configured pinned OPA must exist with expected digest"
    )
    assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected
    return PinnedLocalOPA(path, expected_digest=expected)


def test_actual_rego_success_and_control_failure(evaluator, scope, now):
    policy, plan, evidence = opa_bundle(scope, now, evaluator.expected_digest)
    state = {"evidence": (evidence,)}
    service = OPAPlanPolicy(
        policy_provider=lambda _: policy,
        evidence_provider=lambda _: state["evidence"],
        authenticate_policy=lambda _: None,
        authenticate_evidence=lambda record: record,
        authorize=lambda *_: None,
        evaluator=evaluator,
        holds=SimpleNamespace(tenant_id=scope.tenant_id, active_holds=lambda _: ()),
        clock=lambda: now,
    )
    assert service.evaluate("operator", plan).allowed
    state["evidence"] = (replace(evidence, result=R.FAIL),)
    result = service.evaluate("operator", plan)
    assert not result.allowed and "unverified-control" in result.reasons


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"schema_version": 1, "checks": []},
        {"schema_version": 1, "checks": [{"result": "pass"}]},
        {
            "schema_version": 1,
            "checks": [{}],
            "scope_covered": True,
            "policy_bound": True,
        },
    ],
)
def test_actual_policy_denies_missing_inputs(evaluator, scope, now, body):
    policy, _, _ = opa_bundle(scope, now, evaluator.expected_digest)
    allow, reasons = evaluator.evaluate(policy, body)
    assert not allow and reasons


@pytest.mark.parametrize(
    "builtin", ["opa.runtime()", "time.now_ns()", "uuid.rfc4122()"]
)
def test_capabilities_block_environment_and_nondeterministic_builtins(
    evaluator, scope, now, builtin
):
    policy, _, _ = opa_bundle(scope, now, evaluator.expected_digest)
    source = (
        'package sova.security\nimport rego.v1\ndecision := {"allow":true,"reasons":[]} if { value := '
        + builtin
        + "; value != null }\n"
    )
    with pytest.raises(ContractError, match="rejected"):
        evaluator.evaluate(replace(policy, source=source), {})


def test_capabilities_block_actual_http_attempt(evaluator, scope, now):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(True)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.01), daemon=True
    )
    thread.start()
    try:
        policy, _, _ = opa_bundle(scope, now, evaluator.expected_digest)
        source = (
            'package sova.security\nimport rego.v1\ndecision := {"allow":true,"reasons":[]} if { response := http.send({"method":"GET","url":"http://127.0.0.1:'
            + str(server.server_port)
            + '/canary"}); response.status_code == 200 }\n'
        )
        with pytest.raises(ContractError, match="rejected"):
            evaluator.evaluate(replace(policy, source=source), {})
        assert calls == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_unqualified_capabilities_and_engine_hashes_are_rejected(evaluator, scope, now):
    policy, _, _ = opa_bundle(scope, now, evaluator.expected_digest)
    for changed in [
        replace(policy, engine_digest="0" * 64),
        replace(policy, capabilities_digest="0" * 64),
    ]:
        with pytest.raises(ContractError):
            evaluator.evaluate(changed, {})


@pytest.mark.parametrize(
    "value",
    [
        "true",
        '{"allow":"true","reasons":[]}',
        '{"allow":true,"reasons":["contradiction"]}',
        '{"allow":true,"reasons":[],"commands":["forbidden"]}',
    ],
)
def test_actual_opa_output_cannot_smuggle_commands_or_weak_types(
    evaluator, scope, now, value
):
    policy, _, _ = opa_bundle(scope, now, evaluator.expected_digest)
    source = "package sova.security\nimport rego.v1\ndecision := " + value + "\n"
    with pytest.raises(ContractError):
        evaluator.evaluate(replace(policy, source=source), {})


def test_undefined_actual_policy_is_never_a_cached_allow(evaluator, scope, now):
    policy, _, _ = opa_bundle(scope, now, evaluator.expected_digest)
    policy = replace(policy, source="package another.namespace\nvalue := true\n")
    with pytest.raises(ContractError, match="rejected"):
        evaluator.evaluate(policy, {})
