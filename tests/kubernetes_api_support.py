"""Owned loopback-only API/etcd fixture; never reads kubeconfig or cloud tokens."""

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time
from uuid import uuid4

import pytest


BINARIES = {
    "etcd": "e3d7d2950b4efbebb7c585a5876c2dc7db4a0c4b8ed95939121be853e0c55a27",
    "kube-apiserver": "999e4874de50139f40929d6a9f4844efc66ad09647dc0e84031daca4711f12b6",
}


def tool_directory():
    location = os.environ.get("SOVA_TEST_ENVTEST_DIRECTORY")
    if not location:
        pytest.skip("Explicit pinned local envtest directory required")
    root = Path(location).resolve()
    for name, expected in BINARIES.items():
        path = root / name
        assert path.is_file() and path.stat().st_size < 200_000_000
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected
    return root


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def certificates(root):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    import ipaddress

    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Owned envtest CA")])
    def base(subject, key):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False))
    ca = (base(ca_name, ca_key).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .sign(ca_key, hashes.SHA256()))
    (root / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for name, client in (("server", False), ("admin", True)):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        attrs = [x509.NameAttribute(NameOID.COMMON_NAME, "owned-envtest-admin" if client else "localhost")]
        if client:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, "system:masters"))
        builder = (base(x509.Name(attrs), key).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
        if not client:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        cert = builder.sign(ca_key, hashes.SHA256())
        (root / (name + ".pem")).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (root / (name + ".key")).write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        (root / (name + ".key")).chmod(0o600)
    signing = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (root / "sa.key").write_bytes(signing.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (root / "sa.key").chmod(0o600)
    (root / "sa.pub").write_bytes(signing.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))


class LocalKubernetes:
    def __init__(self, root):
        self.root = root
        self.port = port()
        self.origin = f"https://127.0.0.1:{self.port}"
        self.admin = self.context()
        self.admin.load_cert_chain(str(root / "admin.pem"), str(root / "admin.key"))

    def context(self):
        context = ssl.create_default_context(cafile=str(self.root / "ca.pem"))
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        return context

    def request(self, method, path, body=None, *, credential=None):
        context = self.admin if credential is None else self.context()
        connection = http.client.HTTPSConnection("127.0.0.1", self.port, context=context, timeout=3)
        headers = {"Content-Type": "application/json"}
        if credential is not None:
            headers["Authorization"] = "Bearer " + credential.token
        try:
            connection.request(method, path, body=None if body is None else json.dumps(body).encode(), headers=headers)
            response = connection.getresponse()
            raw = response.read(2_000_001)
            assert len(raw) <= 2_000_000
            data = json.loads(raw) if raw.startswith(b"{") else {}
            return response.status, data
        finally:
            connection.close()

    def create(self, path, body):
        status, data = self.request("POST", path, body)
        assert status == 201, f"Owned fixture create failed: HTTP {status}"
        return data

    def token(self, namespace, service_account, audience, *, secret=None):
        from sova_security.adapters.review_https import BearerCredential
        spec = dict(audiences=[audience], expirationSeconds=600)
        if secret is not None:
            spec["boundObjectRef"] = dict(apiVersion="v1", kind="Secret", name=secret["metadata"]["name"], uid=secret["metadata"]["uid"])
        data = self.create(f"/api/v1/namespaces/{namespace}/serviceaccounts/{service_account}/token",
            dict(apiVersion="authentication.k8s.io/v1", kind="TokenRequest", spec=spec))
        return BearerCredential(data["status"]["token"], datetime.fromisoformat(data["status"]["expirationTimestamp"].replace("Z", "+00:00")))


@contextmanager
def local_kubernetes(root, tools):
    root.mkdir(mode=0o700)
    certificates(root)
    api = LocalKubernetes(root)
    etcd_port, peer_port = port(), port()
    children, logs = [], []
    def start(name, args):
        log = (root / (name + ".log")).open("wb")
        os.chmod(log.name, 0o600)
        logs.append(log)
        process = subprocess.Popen([str(tools / name), *args], stdout=log, stderr=log)
        children.append(process)
        return process
    try:
        etcd = start("etcd", ["--name=sova-envtest", f"--data-dir={root / 'etcd-data'}",
            f"--listen-client-urls=http://127.0.0.1:{etcd_port}", f"--advertise-client-urls=http://127.0.0.1:{etcd_port}",
            f"--listen-peer-urls=http://127.0.0.1:{peer_port}", f"--initial-advertise-peer-urls=http://127.0.0.1:{peer_port}",
            f"--initial-cluster=sova-envtest=http://127.0.0.1:{peer_port}", "--initial-cluster-token=" + uuid4().hex,
            "--quota-backend-bytes=67108864", "--log-level=error"])
        server = start("kube-apiserver", ["--bind-address=127.0.0.1", "--advertise-address=127.0.0.1",
            f"--secure-port={api.port}", f"--etcd-servers=http://127.0.0.1:{etcd_port}",
            "--service-cluster-ip-range=10.96.0.0/24", "--authorization-mode=RBAC", "--anonymous-auth=false",
            f"--client-ca-file={root / 'ca.pem'}", f"--tls-cert-file={root / 'server.pem'}", f"--tls-private-key-file={root / 'server.key'}",
            "--service-account-issuer=https://kubernetes.default.svc", "--api-audiences=kubernetes-api",
            f"--service-account-signing-key-file={root / 'sa.key'}", f"--service-account-key-file={root / 'sa.pub'}"])
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            assert etcd.poll() is None and server.poll() is None, "Owned control plane exited during startup"
            try:
                if api.request("GET", "/readyz")[0] == 200:
                    break
            except (OSError, ssl.SSLError):
                pass
            time.sleep(0.1)
        else:
            raise AssertionError("Owned control plane readiness deadline exceeded")
        yield api
    finally:
        for process in reversed(children):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        for log in logs:
            log.close()
