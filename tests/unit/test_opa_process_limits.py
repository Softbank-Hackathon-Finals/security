"""Controlled child processes exercise quotas; these are not OPA binaries."""

import hashlib
import sys

import pytest

from opa_support import opa_bundle
from sova_security.adapters.opa_local import PinnedLocalOPA
from sova_security.contracts.commands import ContractError


def child(tmp_path, source):
    path = tmp_path / "controlled-engine"
    path.write_text("#!" + sys.executable + "\n" + source + "\n")
    path.chmod(0o700)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def test_local_policy_process_has_a_hard_deadline(tmp_path, scope, now):
    path, digest = child(tmp_path, "import time\ntime.sleep(30)")
    policy, _, _ = opa_bundle(scope, now, digest)
    with pytest.raises(ContractError, match="timed out"):
        PinnedLocalOPA(path, expected_digest=digest, timeout_seconds=1).evaluate(
            policy, {}
        )


def test_closing_output_pipes_does_not_bypass_process_deadline(tmp_path, scope, now):
    path, digest = child(
        tmp_path, "import os,time\nos.close(1)\nos.close(2)\ntime.sleep(30)"
    )
    policy, _, _ = opa_bundle(scope, now, digest)
    with pytest.raises(ContractError, match="timed out"):
        PinnedLocalOPA(path, expected_digest=digest, timeout_seconds=1).evaluate(
            policy, {}
        )


@pytest.mark.parametrize("channel", ["stdout", "stderr"])
def test_oversized_child_output_is_stopped_without_echoing_content(
    tmp_path, scope, now, channel
):
    path, digest = child(
        tmp_path,
        "import sys\nsys."
        + channel
        + '.write("x"*1000000)\nsys.'
        + channel
        + ".flush()",
    )
    policy, _, _ = opa_bundle(scope, now, digest)
    with pytest.raises(ContractError, match="output limit"):
        PinnedLocalOPA(path, expected_digest=digest).evaluate(policy, {})


def test_host_environment_credentials_are_not_inherited_by_policy_process(
    tmp_path, scope, now, monkeypatch
):
    monkeypatch.setenv("SOVA_ENV_CANARY", "not-a-real-credential")
    source = 'import os,json\nassert "SOVA_ENV_CANARY" not in os.environ\nassert "AWS_SECRET_ACCESS_KEY" not in os.environ\nprint(json.dumps({"result":[{"expressions":[{"value":{"allow":True,"reasons":[]}}]}]}))'
    path, digest = child(tmp_path, source)
    policy, _, _ = opa_bundle(scope, now, digest)
    assert PinnedLocalOPA(path, expected_digest=digest).evaluate(policy, {}) == (
        True,
        (),
    )
