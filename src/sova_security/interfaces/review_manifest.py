"""Render an isolated tenant's Kubernetes review host. Never apply resources."""

import argparse
import ipaddress
import json
import re

from sova_security.adapters.review_mounts import mounted_bytes
from sova_security.adapters.vulnerability_reports import bounded_report
from sova_security.contracts.commands import ContractError, identifier


def manifest(config):
    keys = {"namespace", "client_namespace", "client_app", "image", "tenant_id", "review_audience",
            "api_audience", "api_origin", "api_address", "api_port", "database_address", "database_port"}
    if type(config) is not dict or set(config) != keys:
        raise ContractError("Explicit deployment registration fields required")
    for key in ("namespace", "client_namespace", "client_app"):
        if type(config[key]) is not str or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", config[key]):
            raise ContractError("DNS-label deployment identifiers required")
    for key in ("tenant_id", "review_audience", "api_audience"):
        identifier(config[key])
    if config["review_audience"] == config["api_audience"]:
        raise ContractError("Separate service and Kubernetes API token audiences required")
    if type(config["image"]) is not str or not re.fullmatch(r"[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}", config["image"]):
        raise ContractError("Explicit registry image digest required")
    from sova_security.adapters.review_https import HTTPSJSONTransport
    transport = HTTPSJSONTransport(config["api_origin"])
    endpoints = []
    for prefix in ("api", "database"):
        address, port = ipaddress.ip_address(config[prefix + "_address"]), config[prefix + "_port"]
        if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
            raise ContractError("Registered unicast service endpoint required")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ContractError("Registered endpoint port required")
        endpoints.append(dict(to=[dict(ipBlock=dict(cidr=f"{address}/{address.max_prefixlen}"))], ports=[dict(protocol="TCP", port=port)]))
    if transport.port != config["api_port"]:
        raise ContractError("TokenReview origin differs from registered API port")
    name, ns = "security-review", config["namespace"]
    labels = {"app.kubernetes.io/name": name}
    def resource(api, kind, name=name, *, namespaced=True, **fields):
        return dict(apiVersion=api, kind=kind, metadata=dict(name=name, **({"namespace": ns} if namespaced else {})), **fields)
    server_config = dict(schema_version=1, tenant_id=config["tenant_id"], database_dsn_file="/run/database/dsn",
        tokenreview_origin=config["api_origin"], tokenreview_ca_file="/run/api/ca.crt",
        reviewer_token_file="/run/api/token", audience=config["review_audience"],
        grants_file="/run/grants/grants.json", local_audit_file="/var/log/security-review/reviews.jsonl")
    volumes = [dict(name="config", configMap=dict(name=name + "-config")),
        dict(name="tls", secret=dict(secretName=name + "-tls", defaultMode=0o440)),
        dict(name="database", secret=dict(secretName=name + "-database", defaultMode=0o440)),
        dict(name="grants", configMap=dict(name=name + "-grants")),
        dict(name="api", projected=dict(defaultMode=0o440, sources=[
            dict(serviceAccountToken=dict(path="token", audience=config["api_audience"], expirationSeconds=600)),
            dict(configMap=dict(name=name + "-api-ca", items=[dict(key="ca.crt", path="ca.crt")]))])),
        dict(name="audit", persistentVolumeClaim=dict(claimName=name + "-audit")),
        dict(name="tmp", emptyDir=dict(medium="Memory", sizeLimit="16Mi"))]
    mounts = [dict(name=n, mountPath=p, readOnly=True) for n, p in (
        ("config", "/run/config"), ("tls", "/run/tls"), ("database", "/run/database"),
        ("grants", "/run/grants"), ("api", "/run/api"))]
    mounts += [dict(name="audit", mountPath="/var/log/security-review"), dict(name="tmp", mountPath="/tmp")]
    pod = dict(serviceAccountName=name, automountServiceAccountToken=False, enableServiceLinks=False,
        hostNetwork=False, hostPID=False, hostIPC=False, terminationGracePeriodSeconds=10,
        securityContext=dict(runAsNonRoot=True, runAsUser=10001, runAsGroup=10001, fsGroup=10001,
                             seccompProfile=dict(type="RuntimeDefault")), volumes=volumes,
        containers=[dict(name=name, image=config["image"], imagePullPolicy="IfNotPresent",
            command=["python", "-m", "sova_security.interfaces.review_server"],
            args=["--config", "/run/config/config.json", "--certificate", "/run/tls/tls.crt",
                  "--private-key", "/run/tls/tls.key", "--host", "0.0.0.0", "--port", "8443"],
            env=[dict(name="PYTHONDONTWRITEBYTECODE", value="1"), dict(name="PYTHONUNBUFFERED", value="1")],
            securityContext=dict(allowPrivilegeEscalation=False, readOnlyRootFilesystem=True,
                                 capabilities=dict(drop=["ALL"])), ports=[dict(name="https", containerPort=8443)],
            resources=dict(requests=dict(cpu="100m", memory="128Mi"), limits=dict(cpu="1", memory="256Mi")),
            volumeMounts=mounts, readinessProbe=dict(tcpSocket=dict(port="https"), initialDelaySeconds=2, periodSeconds=5),
            livenessProbe=dict(tcpSocket=dict(port="https"), initialDelaySeconds=10, periodSeconds=10))])
    role_name = ns + "-security-review"
    items = [resource("v1", "ServiceAccount", automountServiceAccountToken=False),
        resource("rbac.authorization.k8s.io/v1", "ClusterRole", role_name, namespaced=False,
            rules=[dict(apiGroups=["authentication.k8s.io"], resources=["tokenreviews"], verbs=["create"])]),
        resource("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", role_name, namespaced=False,
            roleRef=dict(apiGroup="rbac.authorization.k8s.io", kind="ClusterRole", name=role_name),
            subjects=[dict(kind="ServiceAccount", name=name, namespace=ns)]),
        resource("v1", "ConfigMap", name + "-config", data={"config.json": json.dumps(server_config, sort_keys=True)}),
        resource("apps/v1", "Deployment", spec=dict(replicas=1, strategy=dict(type="Recreate"),
            selector=dict(matchLabels=labels), template=dict(metadata=dict(labels=labels), spec=pod))),
        resource("v1", "Service", spec=dict(type="ClusterIP", selector=labels, ports=[dict(name="https", port=8443, targetPort="https")])),
        resource("networking.k8s.io/v1", "NetworkPolicy", spec=dict(podSelector=dict(matchLabels=labels),
            policyTypes=["Ingress", "Egress"], ingress=[{"from": [dict(namespaceSelector=dict(matchLabels={"kubernetes.io/metadata.name": config["client_namespace"]}),
                podSelector=dict(matchLabels={"app.kubernetes.io/name": config["client_app"]}))], "ports": [dict(protocol="TCP", port=8443)]}],
            egress=endpoints + [dict(to=[dict(namespaceSelector=dict(matchLabels={"kubernetes.io/metadata.name": "kube-system"}),
                podSelector=dict(matchLabels={"k8s-app": "kube-dns"}))], ports=[dict(protocol=p, port=53) for p in ("UDP", "TCP")])]))]
    return dict(apiVersion="v1", kind="List", items=items)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registration", required=True)
    args = parser.parse_args()
    try:
        result = manifest(bounded_report(mounted_bytes(args.registration, limit=16384)))
    except Exception:
        parser.exit(2, "Invalid explicit deployment registration.\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
