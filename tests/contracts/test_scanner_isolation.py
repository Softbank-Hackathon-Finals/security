"""Scanner supply-chain containment must not weaken evidence collection."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess

import pytest


spec = importlib.util.spec_from_file_location("isolated_scan", Path(__file__).resolve().parents[2] / "scripts" / "scan_service_image.py")
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


def command(tmp_path, **changes):
    options = dict(image_id="sha256:" + "a" * 64, trivy=tmp_path / "tool", inputs=tmp_path / "inputs",
                   cache=tmp_path / "cache", results=tmp_path / "results", uid=1001, gid=1001,
                   network="none", arguments=["image", "--input", "/scan-input/image.tar"], invocation="b" * 32)
    options.update(changes)
    return scanner.scanner_command(**options)


def test_scanner_receives_only_owned_archive_tool_cache_and_results(tmp_path):
    args = command(tmp_path)
    mounts = [args[i + 1] for i, value in enumerate(args) if value == "--mount"]
    assert len(mounts) == 4
    assert all("docker.sock" not in value and ".git" not in value for value in args)
    assert all(value.endswith(",readonly") for value in mounts if "dst=/scan-tool" in value or "dst=/scan-input" in value)
    assert "--network=none" in args and "--read-only" in args and "--cap-drop=ALL" in args
    assert "--security-opt=no-new-privileges" in args and "--pull=never" in args
    assert "--privileged" not in args and "--pid=host" not in args and "--network=host" not in args
    assert args[args.index("--user") + 1] == "1001:1001"
    assert [value for value in args if value.startswith("--env")] == ["--env=HOME=/tmp", "--env=TMPDIR=/scan-cache/tmp"]


@pytest.mark.parametrize("changes", [{"uid": 0}, {"gid": 0}, {"network": "host"},
                                     {"trivy": Path("relative")}, {"inputs": Path("/tmp/inject,readonly")}])
def test_scanner_rejects_root_host_network_and_mount_injection(tmp_path, changes):
    with pytest.raises(ValueError):
        command(tmp_path, **changes)


def test_scanner_artifact_is_a_bounded_single_link_regular_file(tmp_path):
    result = tmp_path / "result.json"
    result.write_bytes(b"{}")
    assert scanner.scanner_file(tmp_path, "result.json", 2) == result
    with pytest.raises(ValueError):
        scanner.scanner_file(tmp_path, "result.json", 1)
    with pytest.raises(ValueError):
        scanner.scanner_file(tmp_path, "../result.json", 10)
    with pytest.raises(ValueError):
        scanner.scanner_file(tmp_path, str(result), 10)
    with pytest.raises(ValueError):
        scanner.scanner_file(tmp_path, ".", 10)
    result.write_bytes(b"")
    with pytest.raises(ValueError):
        scanner.scanner_file(tmp_path, "result.json", 10)


@pytest.mark.skipif(os.name == "nt", reason="CI Linux scanner filesystem boundary")
@pytest.mark.parametrize("fault", ["file-symlink", "parent-symlink", "hardlink", "fifo"])
def test_scanner_cannot_export_host_files_through_special_files(tmp_path, fault):
    owned = tmp_path / "owned"
    owned.mkdir()
    outside = tmp_path / "private.json"
    outside.write_bytes(b"host-private-fixture")
    result = owned / "result.json"
    relative = "result.json"
    if fault == "file-symlink":
        result.symlink_to(outside)
    elif fault == "parent-symlink":
        (owned / "parent").symlink_to(tmp_path, target_is_directory=True)
        relative = "parent/private.json"
    elif fault == "hardlink":
        os.link(outside, result)
    else:
        os.mkfifo(result)
    with pytest.raises(ValueError):
        scanner.scanner_file(owned, relative, 4096)


@pytest.mark.parametrize("stderr,code,expected", [
    (b"private fixture permission denied https://private.invalid/path", 1, "permission-denied"),
    (b"private fixture x509 unknown authority", 1, "tls-authority"),
    (b"private fixture no space left on device", 1, "storage-full"),
    (b"private fixture", 137, "resource-limit"),
    (b"private fixture", 1, "unclassified"),
])
def test_failure_diagnostics_never_include_subprocess_details(stderr, code, expected):
    assert scanner.failure_category(subprocess.CompletedProcess([], code, b"", stderr)) == expected


@pytest.mark.parametrize("fault", [None, "image", "name", "label", "multiple"])
def test_cleanup_requires_owned_container_identity_before_deleting(fault):
    calls = []
    invocation, identity, image = "b" * 32, "c" * 64, "sha256:" + "a" * 64
    record = {"Id": identity, "Image": image, "Name": "/sova-image-scan-" + invocation,
              "Config": {"Labels": {"sova.scanner.invocation": invocation}}}
    if fault == "image":
        record["Image"] = "sha256:" + "d" * 64
    elif fault == "name":
        record["Name"] = "/other-container"
    elif fault == "label":
        record["Config"]["Labels"] = {}

    def run(args, **_):
        calls.append(args)
        if args[2] == "ls":
            return (identity + ("\n" + "d" * 64 if fault == "multiple" else "") + "\n").encode()
        if args[2] == "inspect":
            return json.dumps([record]).encode()
        assert args == ["docker", "container", "rm", "--force", identity]
        return b""

    if fault:
        with pytest.raises(RuntimeError):
            scanner.cleanup_scanner(run, invocation=invocation, image_id=image)
        assert not any(args[2] == "rm" for args in calls)
    else:
        scanner.cleanup_scanner(run, invocation=invocation, image_id=image)
        assert calls[-1] == ["docker", "container", "rm", "--force", identity]
