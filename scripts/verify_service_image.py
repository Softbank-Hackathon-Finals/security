"""Inside-image, network-free checks; writes no files and emits no credentials."""

import errno
from importlib import metadata, util
import json
import os
from pathlib import Path
import sys
import subprocess
import re
import platform

import cryptography
import psycopg
import uvicorn


def os_inventory(target_platform):
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    family = release.get("ID", "").strip('"')
    if family == "alpine":
        assert re.fullmatch(r"3\.24\.[0-9]+", release.get("VERSION_ID", "").strip('"'))
        # Keep the real APK database in the runtime. No file-only copy that
        # hides installed libraries from the scanner is accepted.
        database = Path("/lib/apk/db/installed").read_bytes()
        assert 0 < len(database) <= 1024 * 1024
        packages = []
        for block in database.decode("utf-8").strip().split("\n\n"):
            identity = {}
            for line in block.splitlines():
                if line[:2] in {"P:", "V:", "A:"}:
                    assert line[0] not in identity, "Duplicate APK identity"
                    identity[line[0]] = line[2:]
            assert set(identity) == {"P", "V", "A"}, "Incomplete APK identity"
            assert identity["A"] in {"x86_64" if target_platform == "linux/amd64" else "aarch64", "noarch"}
            assert all(identity.values())
            packages.append((identity["P"], identity["V"], identity["A"]))
        return family, packages
    assert family == "debian"
    query = subprocess.run(["/usr/bin/dpkg-query", "--admindir=/var/lib/dpkg", "-W",
        "-f=${Package}\\t${Version}\\t${Architecture}\\t${db:Status-Status}\\t${db:Status-Eflag}\\n"],
        check=True, capture_output=True, timeout=5, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    assert len(query.stdout) <= 262144, "OS inventory exceeds qualification bound"
    packages = []
    for row in query.stdout.decode("utf-8").splitlines():
        fields = row.split("\t")
        assert len(fields) == 5 and fields[3:] == ["installed", "ok"], "Incomplete OS package state"
        assert fields[2] in {"amd64" if target_platform == "linux/amd64" else "arm64", "all"}, "Unexpected image architecture"
        packages.append(tuple(fields[:3]))
    return family, packages

def main():
    assert os.getuid() == os.getgid() == 10001
    assert sys.prefix == "/opt/service"
    assert cryptography and psycopg and uvicorn
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    assert int(status["CapEff"].strip(), 16) == 0
    assert status["NoNewPrivs"].strip() == "1"
    for module in ("pytest", "ruff", "fastapi", "boto3", "pip", "ensurepip"):
        assert util.find_spec(module) is None, "Development/cloud dependencies must not be in the service environment"
    global_site = Path(sys.base_prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
    assert not list(metadata.distributions(path=[str(global_site)])), "Base global installer packages must be removed"
    assert not list(Path(sys.base_prefix, "bin").glob("pip*")), "Installer entry points must be removed"
    try:
        fd = os.open("/app/forbidden-write", os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    except OSError as error:
        assert error.errno in (errno.EROFS, errno.EACCES)
    else:
        os.close(fd)
        raise AssertionError("Root filesystem must reject writes")
    manifest = json.loads(Path("/app/build-manifest.json").read_text())
    target_platform = manifest["platform"]
    assert target_platform in {"linux/amd64", "linux/arm64"}
    assert platform.machine() == {"linux/amd64": "x86_64", "linux/arm64": "aarch64"}[target_platform]
    assert metadata.version("sova-security") == manifest["version"]
    assert manifest["execution_authorized"] is False and manifest["signed_attestation"] is False
    inventory = sorted((item.metadata["Name"], item.version) for item in metadata.distributions())
    family, packages = os_inventory(target_platform)
    assert packages and len(packages) == len(set(packages))
    print(json.dumps(dict(commit_sha=manifest["commit_sha"], uid=os.getuid(), dependencies=inventory,
                          global_python_packages=[], package_installers_absent=True,
                          platform=target_platform, os_family=family, os_packages=sorted(packages),
                          root_write_denied=True, effective_capabilities=0, no_new_privileges=True)))


if __name__ == "__main__":
    main()
