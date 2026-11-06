import pytest

from sova_security.contracts.commands import ContractError
from sova_security.interfaces.review_manifest import manifest


def registration():
    return dict(namespace="security-tenant-a", client_namespace="platform", client_app="control-gate",
        image="registry.example.invalid/review@sha256:" + "a" * 64, tenant_id="tenant-a",
        review_audience="security-review", api_audience="kubernetes-api", api_origin="https://api.example.invalid:6443",
        api_address="10.0.0.1", api_port=6443, database_address="10.0.0.2", database_port=5432)


def test_deployment_has_no_execution_privilege_and_restricts_ingress_egress():
    result = manifest(registration())
    items = {v["kind"]: v for v in result["items"]}
    assert items["ClusterRole"]["rules"] == [dict(apiGroups=["authentication.k8s.io"], resources=["tokenreviews"], verbs=["create"])]
    assert items["ClusterRoleBinding"]["subjects"] == [dict(kind="ServiceAccount", name="security-review", namespace="security-tenant-a")]
    pod = items["Deployment"]["spec"]["template"]["spec"]
    assert not pod["automountServiceAccountToken"] and not pod["hostNetwork"]
    container = pod["containers"][0]
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert container["securityContext"]["readOnlyRootFilesystem"]
    assert all("hostPath" not in v for v in pod["volumes"])
    assert all("subPath" not in m for m in container["volumeMounts"])  # projected rotation remains visible
    policy = items["NetworkPolicy"]["spec"]
    assert policy["policyTypes"] == ["Ingress", "Egress"]
    peer = policy["ingress"][0]["from"][0]
    assert "namespaceSelector" in peer and "podSelector" in peer
    assert [row["to"][0]["ipBlock"]["cidr"] for row in policy["egress"][:2]] == ["10.0.0.1/32", "10.0.0.2/32"]
    assert "Secret" not in items  # no generated passwords, issuer or enrollment credentials


@pytest.mark.parametrize("key,value", [
    ("image", "registry.example.invalid/review:latest"), ("namespace", "default/other"),
    ("api_origin", "http://api.example.invalid:6443"), ("api_port", 443),
    ("api_address", "0.0.0.0"), ("database_address", "169.254.169.254"),
    ("database_address", "10.0.0.0/8"), ("database_port", True), ("review_audience", "kubernetes-api"),
])
def test_deployment_requires_exact_registered_destinations(key, value):
    config = registration()
    config[key] = value
    with pytest.raises((ContractError, ValueError)):
        manifest(config)
