"""Inside-image, network-free checks; writes no files and emits no credentials."""

import errno
from importlib import metadata, util
import json
import os
from pathlib import Path
import sys

import cryptography
import psycopg
import uvicorn


def main():
    assert os.getuid() == os.getgid() == 10001
    assert sys.prefix == "/opt/service"
    assert cryptography and psycopg and uvicorn
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    assert int(status["CapEff"].strip(), 16) == 0
    assert status["NoNewPrivs"].strip() == "1"
    for module in ("pytest", "ruff", "fastapi", "boto3"):
        assert util.find_spec(module) is None, "Development/cloud dependencies must not be in the service environment"
    try:
        fd = os.open("/app/forbidden-write", os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    except OSError as error:
        assert error.errno in (errno.EROFS, errno.EACCES)
    else:
        os.close(fd)
        raise AssertionError("Root filesystem must reject writes")
    manifest = json.loads(Path("/app/build-manifest.json").read_text())
    assert metadata.version("sova-security") == manifest["version"]
    assert manifest["execution_authorized"] is False and manifest["signed_attestation"] is False
    inventory = sorted((item.metadata["Name"], item.version) for item in metadata.distributions())
    print(json.dumps(dict(commit_sha=manifest["commit_sha"], uid=os.getuid(), dependencies=inventory,
                          root_write_denied=True, effective_capabilities=0, no_new_privileges=True)))


if __name__ == "__main__":
    main()
