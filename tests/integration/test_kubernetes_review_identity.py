"""Actual Kubernetes 1.35 TokenRequest/TokenReview and RBAC; no kubelet/CNI."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from kubernetes_api_support import local_kubernetes, tool_directory
from sova_security.adapters.review_https import HTTPSJSONTransport
from sova_security.adapters.review_identity import TokenReviewAuthenticator, WorkloadGrant
from sova_security.contracts.commands import ResourceScope
from sova_security.domain.review_service import ReviewPrincipal
from sova_security.interfaces.review_manifest import manifest

pytestmark = pytest.mark.kubernetes_api


@pytest.fixture(scope="module")
def api(tmp_path_factory):
    tools = tool_directory()
    with local_kubernetes(tmp_path_factory.mktemp("owned-kubernetes") / "control-plane", tools) as value:
        yield value


@pytest.fixture
def workload(api):
    ns = "review-" + uuid4().hex[:12]
    api.create("/api/v1/namespaces", dict(apiVersion="v1", kind="Namespace", metadata=dict(name=ns)))
    config = dict(namespace=ns, client_namespace=ns, client_app="consumer",
        image="registry.example.invalid/review@sha256:" + "a" * 64, tenant_id="tenant-a",
        review_audience="security-review", api_audience="kubernetes-api", api_origin="https://kubernetes.default.svc",
        api_address="10.96.0.1", api_port=443, database_address="10.0.0.2", database_port=5432)
    resources = manifest(config)["items"]
    paths = dict(ServiceAccount=f"/api/v1/namespaces/{ns}/serviceaccounts",
        ClusterRole="/apis/rbac.authorization.k8s.io/v1/clusterroles",
        ClusterRoleBinding="/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
        ConfigMap=f"/api/v1/namespaces/{ns}/configmaps", Deployment=f"/apis/apps/v1/namespaces/{ns}/deployments",
        Service=f"/api/v1/namespaces/{ns}/services", NetworkPolicy=f"/apis/networking.k8s.io/v1/namespaces/{ns}/networkpolicies")
    for resource in resources[:3]:
        api.create(paths[resource["kind"]], resource)
    worker = api.create(paths["ServiceAccount"], dict(apiVersion="v1", kind="ServiceAccount", metadata=dict(name="consumer"), automountServiceAccountToken=False))
    secret = api.create(f"/api/v1/namespaces/{ns}/secrets", dict(apiVersion="v1", kind="Secret", metadata=dict(name="lease"), type="Opaque"))
    reviewer = api.token(ns, "security-review", "kubernetes-api")
    client = api.token(ns, "consumer", "security-review", secret=secret)
    now = datetime.now(UTC)
    scope = ResourceScope("tenant-a", "app-a", "test", "review")
    principal = ReviewPrincipal("consumer", scope.tenant_id, (scope,), ("enforce", "shadow"), now, now + timedelta(minutes=5), "a" * 64)
    grant = WorkloadGrant(f"system:serviceaccount:{ns}:consumer", worker["metadata"]["uid"], principal)
    state = SimpleNamespace(grant=grant, reviewer=reviewer)
    auth = TokenReviewAuthenticator(audience="security-review", transport=HTTPSJSONTransport(api.origin, tls_context=api.context()),
        reviewer_credential=lambda: state.reviewer,
        grant_for=lambda username, uid: state.grant if state.grant and (state.grant.username, state.grant.uid) == (username, uid) else None,
        clock=lambda: datetime.now(UTC))
    deadline = time.monotonic() + 10
    while auth(client.token) is None and time.monotonic() < deadline:
        time.sleep(0.1)
    assert auth(client.token) is not None, "Actual TokenReview positive control failed"
    return SimpleNamespace(ns=ns, auth=auth, state=state, client=client, secret=secret, worker=worker,
                           resources=resources, paths=paths, api=api)


def until_rejected(workload):
    start = time.monotonic()
    while time.monotonic() - start < 30:
        if workload.auth(workload.client.token) is None:
            return time.monotonic() - start
        time.sleep(0.1)
    raise AssertionError("Bound credential remained accepted past local revocation deadline")


def test_actual_audience_uid_and_reviewer_credential_are_enforced(workload):
    w = workload
    result = w.auth(w.client.token)
    assert result.subject_id == "consumer" and result.scopes == w.state.grant.principal.scopes
    other = w.api.token(w.ns, "consumer", "different-service", secret=w.secret)
    assert w.auth(other.token) is None
    original = w.state.grant
    w.state.grant = replace(original, uid="unregistered-uid")
    assert w.auth(w.client.token) is None
    w.state.grant = original
    w.state.reviewer = w.client  # The service-audience token is not an API credential.
    assert w.auth(w.client.token) is None


@pytest.mark.parametrize("fault", ["multi-audience", "long-lifetime"])
def test_service_rejects_broad_credentials_that_actual_tokenreview_accepts(workload, fault):
    w = workload
    spec = dict(audiences=["security-review"], expirationSeconds=600,
                boundObjectRef=dict(apiVersion="v1", kind="Secret", name=w.secret["metadata"]["name"],
                                    uid=w.secret["metadata"]["uid"]))
    if fault == "multi-audience":
        spec["audiences"].append("kubernetes-api")
    else:
        spec["expirationSeconds"] = 3600
    issued = w.api.create(f"/api/v1/namespaces/{w.ns}/serviceaccounts/consumer/token",
                         dict(apiVersion="authentication.k8s.io/v1", kind="TokenRequest", spec=spec))
    token = issued["status"]["token"]
    status, response = w.api.request("POST", "/apis/authentication.k8s.io/v1/tokenreviews",
        dict(apiVersion="authentication.k8s.io/v1", kind="TokenReview", spec=dict(token=token, audiences=["security-review"])),
        credential=w.state.reviewer)
    assert status == 201 and response["status"]["authenticated"] is True
    assert response["status"]["audiences"] == ["security-review"]
    assert w.auth(token) is None
    assert w.auth(w.client.token) is not None


def test_bound_secret_deletion_and_same_name_recreation_do_not_resurrect_token(workload, record_property):
    w = workload
    status, _ = w.api.request("DELETE", f"/api/v1/namespaces/{w.ns}/secrets/lease")
    assert status == 200
    record_property("bound_secret_revocation_seconds", until_rejected(w))
    fresh = w.api.create(f"/api/v1/namespaces/{w.ns}/secrets", dict(apiVersion="v1", kind="Secret", metadata=dict(name="lease"), type="Opaque"))
    assert fresh["metadata"]["uid"] != w.secret["metadata"]["uid"]
    assert w.auth(w.client.token) is None
    renewed = w.api.token(w.ns, "consumer", "security-review", secret=fresh)
    assert w.auth(renewed.token) is not None


def test_service_account_recreation_requires_new_registered_uid(workload, record_property):
    w = workload
    status, _ = w.api.request("DELETE", f"/api/v1/namespaces/{w.ns}/serviceaccounts/consumer")
    assert status == 200
    record_property("service_account_revocation_seconds", until_rejected(w))
    replacement = w.api.create(w.paths["ServiceAccount"], dict(apiVersion="v1", kind="ServiceAccount", metadata=dict(name="consumer")))
    assert replacement["metadata"]["uid"] != w.state.grant.uid
    renewed = w.api.token(w.ns, "consumer", "security-review", secret=w.secret)
    assert w.auth(renewed.token) is None
    w.state.grant = replace(w.state.grant, uid=replacement["metadata"]["uid"])
    assert w.auth(renewed.token) is not None


def test_reviewer_cannot_read_secrets_mint_tokens_or_mutate_workloads_and_rbac(workload):
    w = workload
    attempts = [
        ("GET", f"/api/v1/namespaces/{w.ns}/secrets/lease", None),
        ("POST", f"/api/v1/namespaces/{w.ns}/serviceaccounts/consumer/token",
         dict(apiVersion="authentication.k8s.io/v1", kind="TokenRequest", spec=dict(audiences=["kubernetes-api"], expirationSeconds=600))),
        ("POST", w.paths["Deployment"], next(r for r in w.resources if r["kind"] == "Deployment")),
        ("POST", w.paths["ClusterRoleBinding"], next(r for r in w.resources if r["kind"] == "ClusterRoleBinding")),
    ]
    for method, path, body in attempts:
        status, _ = w.api.request(method, path, body, credential=w.state.reviewer)
        assert status == 403
    assert w.auth(w.client.token) is not None  # The intended permission still works.
    binding = next(r for r in w.resources if r["kind"] == "ClusterRoleBinding")
    status, _ = w.api.request("DELETE", w.paths["ClusterRoleBinding"] + "/" + binding["metadata"]["name"])
    assert status == 200
    assert until_rejected(w) < 30


def test_generated_resources_pass_actual_api_dry_run(workload):
    w = workload
    for resource in w.resources[3:]:
        status, _ = w.api.request("POST", w.paths[resource["kind"]] + "?dryRun=All", resource)
        assert status == 201
    # Acceptance by the API validates object shape only. No pod, network policy
    # enforcement, persistent volume or production image is qualified here.
