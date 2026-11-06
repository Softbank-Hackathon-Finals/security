"""Actual local TLS server and ephemeral test CA; never contact cloud endpoints."""

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import socket
import ipaddress
import threading
import time
import subprocess
import sys
import ssl
import os


def certificates(directory, *, name="server", dns_only=False):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sova local service test CA")])
    ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
          .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
              data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
              encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")] +
                ([] if dns_only else [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    paths = [directory / (name + suffix) for suffix in ("-ca.pem", ".pem", ".key")]
    paths[0].write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    paths[1].write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    paths[2].write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    paths[2].chmod(0o600)
    return paths


@contextmanager
def tls_server(app, directory, *, name="server", dns_only=False):
    import uvicorn

    ca, certificate, key = certificates(directory, name=name, dns_only=dns_only)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    port = listener.getsockname()[1]
    config = uvicorn.Config(app, host="127.0.0.1", port=port, ssl_certfile=str(certificate), ssl_keyfile=str(key),
                            proxy_headers=False, access_log=False, log_level="critical", lifespan="off",
                            limit_concurrency=32, timeout_graceful_shutdown=2)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    try:
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started, "Local TLS server failed to start"
        yield f"https://127.0.0.1:{port}", ca
    finally:
        server.should_exit = True
        thread.join(5)
        listener.close()
        assert not thread.is_alive(), "Local TLS server did not stop"


@contextmanager
def review_process(config_path, directory):
    """Independent service process using the packaged entry module and direct TLS."""
    if os.environ.get("SOVA_TEST_REVIEW_IMAGE"):
        from container_review_support import container_review_process
        with container_review_process(config_path, directory) as server:
            yield server
        return
    ca, certificate, key = certificates(directory, name="process")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    with (directory / "process-stderr.txt").open("wb") as diagnostics:
        child = subprocess.Popen([sys.executable, "-m", "sova_security.interfaces.review_server",
            "--config", str(config_path), "--certificate", str(certificate), "--private-key", str(key),
            "--host", "127.0.0.1", "--port", str(port)], stdout=subprocess.DEVNULL, stderr=diagnostics)
        deadline = time.monotonic() + 10
        context = ssl.create_default_context(cafile=str(ca))
        try:
            while time.monotonic() < deadline:
                assert child.poll() is None, "Isolated review service exited during startup"
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2) as connection:
                        with context.wrap_socket(connection, server_hostname="127.0.0.1"):
                            break
                except (OSError, ssl.SSLError):
                    time.sleep(0.02)
            else:
                raise AssertionError("Isolated review service startup deadline exceeded")
            yield f"https://127.0.0.1:{port}", ca
        finally:
            child.terminate()
            try:
                child.wait(timeout=8)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
