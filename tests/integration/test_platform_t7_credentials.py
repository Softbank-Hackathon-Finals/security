"""Actual pinned T7 acquire and Kubernetes API; issuer proxy is a test shim.

No Tailscale proxy or kubelet is running here. The shim supplies the issuer's
workload group and uses the owned API admin for issuance. Target bearer checks,
TokenRequest, TokenReview and bound object enforcement use the actual API.
"""

from datetime import UTC, datetime
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from test_kubernetes_review_identity import api as owned_api, workload as owned_workload
from sova_security.adapters.platform_review import PLATFORM_BASELINES
from sova_security.adapters.review_identity import ExecCredentialProvider
from sova_security.adapters.review_mounts import MountedTokenCredential
from sova_security.contracts.commands import ContractError

api, workload = owned_api, owned_workload
pytestmark = pytest.mark.kubernetes_api


@pytest.fixture
def t7():
    location = os.environ.get("SOVA_PLATFORM_SOURCE")
    if not location:
        pytest.skip("Explicit pinned platform source required")
    root = Path(location).resolve()
    git = ["git", "-c", f"safe.directory={root.as_posix()}", "-C", str(root)]
    assert subprocess.check_output(git + ["rev-parse", "HEAD"], text=True).strip() in PLATFORM_BASELINES
    assert not subprocess.check_output(git + ["status", "--porcelain"])
    path = root / "infra/envs/rehearsal-access/credentials.py"
    assert path.is_file(), "Qualified source must include the actual T7 credential module"
    spec = importlib.util.spec_from_file_location("qualified_platform_t7", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(spec.name, None)


@pytest.mark.parametrize("audience", ["kubernetes-api", "security-review"])
def test_actual_t7_api_credential_is_not_a_service_audience_provider(t7, workload, audience):
    w = workload
    status, cluster = w.api.request("GET", "/api/v1/namespaces/kube-system")
    assert status == 200
    registration = t7.Registration(cluster["metadata"]["uid"], w.ns, "consumer", w.worker["metadata"]["uid"],
        "tag:owned-issuer", audience, t7.Endpoint("https://issuer.example.invalid", "issuer.owned.ts.net"),
        t7.Endpoint("https://target.example.invalid", "target.owned.ts.net"))
    anchor = w.api.create(f"/api/v1/namespaces/{w.ns}/secrets", dict(apiVersion="v1", kind="Secret",
        metadata=dict(name=registration.name), type="Opaque"))
    target_status = []
    def call(endpoint, method, path, body=None, *, token=None):
        if endpoint == registration.issuer and path == t7.SSR:
            return {"status": {"userInfo": {"groups": [registration.issuer_group]}}}
        status, data = w.api.request(method, path, body,
            credential=None if token is None else SimpleNamespace(token=token))
        if endpoint == registration.target:
            target_status.append(status)
        if status not in (200, 201):
            raise t7.APIError("Owned API rejected credential")
        return data
    provider = ExecCredentialProvider(lambda: t7.acquire(registration, anchor["metadata"]["uid"], call=call),
        clock=lambda: datetime.now(UTC))
    if audience == "kubernetes-api":
        credential = provider()
        assert target_status == [201]
        assert w.auth(credential.token) is None  # API token cannot satisfy service audience.
    else:
        with pytest.raises(ContractError, match="Current host-issued credential unavailable"):
            provider()
        assert target_status == [401]  # Current T7's final SelfSubjectReview is API-only.


def test_pod_bound_projected_source_rotates_without_an_api_audience_or_new_issuer(workload, tmp_path):
    w = workload
    pod = w.api.create(f"/api/v1/namespaces/{w.ns}/pods", dict(apiVersion="v1", kind="Pod", metadata=dict(name="consumer"),
        spec=dict(serviceAccountName="consumer", automountServiceAccountToken=False,
            containers=[dict(name="consumer", image="example.invalid/never-run:fixture")],
            volumes=[dict(name="review-identity", projected=dict(sources=[dict(serviceAccountToken=dict(
                audience="security-review", expirationSeconds=600, path="token"))]))])))
    path = tmp_path / "projected-token"
    provider = MountedTokenCredential(path, clock=lambda: datetime.now(UTC))
    def rotate():
        issued = w.api.token(w.ns, "consumer", "security-review", pod=pod)
        incoming = tmp_path / "replacement"
        incoming.write_text(issued.token)
        incoming.chmod(0o600)
        incoming.replace(path)
    rotate()
    assert w.auth(provider().token) is not None
    assert w.api.request("POST", "/apis/authentication.k8s.io/v1/selfsubjectreviews",
        dict(apiVersion="authentication.k8s.io/v1", kind="SelfSubjectReview"), credential=provider())[0] == 401
    rotate()
    assert w.auth(provider().token) is not None
    path.unlink()
    with pytest.raises(OSError):
        provider()  # No cached credential or alternate token source.
    # The API accepted the projection and Pod binding. Actual kubelet rotation,
    # mount permissions and a running workload remain separate deployment tests.
