"""Opt-in Docker fixture for an already-built, exact local image ID.

This never pulls/publishes images, uses a daemon credential, mounts a repository,
or contacts a deployed cluster. The host network is for owned loopback fixtures;
it does not qualify Kubernetes NetworkPolicy or the deployment's UID mapping.
"""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time
from uuid import uuid4

from tls_review_support import certificates


def docker(*arguments):
    result = subprocess.run(["docker", *arguments], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    assert result.returncode == 0, "Owned test image/container command failed"
    return result.stdout


@contextmanager
def container_review_process(config_path, directory):
    from psycopg.conninfo import conninfo_to_dict

    image = os.environ["SOVA_TEST_REVIEW_IMAGE"]
    revision = os.environ.get("SOVA_TEST_REVIEW_IMAGE_COMMIT", "")
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", image), "An exact locally built image ID is required"
    assert re.fullmatch(r"[0-9a-f]{40}", revision), "An exact tested source revision is required"
    description, = json.loads(docker("image", "inspect", image))
    assert description["Id"] == image and description["Config"]["User"] == "10001:10001"
    assert description["Config"]["Labels"]["org.opencontainers.image.revision"] == revision
    assert os.name == "posix" and os.getuid() > 0, "Private fixture mounts require a non-root Linux runner"
    directory = Path(directory).resolve(strict=True)
    config_path = Path(config_path).resolve(strict=True)
    assert config_path.parent == directory
    config = json.loads(config_path.read_text())
    # All privileged input files must be generated inside this one test directory.
    for field in ("database_dsn_file", "tokenreview_ca_file", "reviewer_token_file", "grants_file"):
        assert Path(config[field]).resolve(strict=True).parent == directory
    audit = Path(config["local_audit_file"])
    assert audit.parent == directory and not audit.exists()
    audit.touch(mode=0o600, exist_ok=False)
    connection = conninfo_to_dict(Path(config["database_dsn_file"]).read_text())
    socket_path = Path(connection["host"]).resolve(strict=True)
    assert socket_path.is_dir() and socket_path.is_absolute() and str(socket_path) != "/"
    ca, certificate, key = certificates(directory, name="container")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    name = "sova-review-test-" + uuid4().hex
    command = ["run", "--pull=never", "--name", name, "--network=host", "--read-only",
               "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=64", "--memory=384m",
               "--user", f"{os.getuid()}:{os.getgid()}",
               "--mount", f"type=bind,source={directory},target={directory},readonly",
               "--mount", f"type=bind,source={audit},target={audit}",
               "--mount", f"type=bind,source={socket_path},target={socket_path},readonly",
               image, "--config", str(config_path), "--certificate", str(certificate), "--private-key", str(key),
               "--host", "127.0.0.1", "--port", str(port)]
    with (directory / "container-stderr.txt").open("wb") as diagnostics:
        child = subprocess.Popen(["docker", *command], stdout=subprocess.DEVNULL, stderr=diagnostics)
        try:
            deadline = time.monotonic() + 15
            context = ssl.create_default_context(cafile=str(ca))
            while time.monotonic() < deadline:
                assert child.poll() is None, "Owned container exited during startup"
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2) as stream:
                        with context.wrap_socket(stream, server_hostname="127.0.0.1"):
                            break
                except (OSError, ssl.SSLError):
                    time.sleep(0.02)
            else:
                raise AssertionError("Owned container startup deadline exceeded")
            yield f"https://127.0.0.1:{port}", ca
        finally:
            docker("rm", "--force", name)
            child.wait(timeout=10)
