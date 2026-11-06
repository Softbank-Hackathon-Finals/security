"""Collect public image vulnerability evidence; never publish or authorize release.

A successful exit means the scan ran and its coverage/identity were checked.
Read decision.json for PASS/BLOCK/UNKNOWN. Even PASS is only this scanner policy.
Local Docker config IDs are NOT registry distribution digests or attestations.
"""

import argparse
from collections import Counter
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tempfile

from sova_security.adapters.bounded_json import bounded_json_object

TRIVY_VERSION = "0.76.2"
TRIVY_SHA256 = "6a972c69606c7b3ea4c6bdcc6fc9332ea9ad38381624310c1e85cc77345909f3"
TRIVY_ARM64_SHA256 = "7844c3851b28470b6d7f0975fa0b3262c5b2272c9a54a91f522801bb8926f51f"
LEVELS = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
MINIMUM_FREE_BYTES = 6 * 1024 ** 3


def require_scan_capacity(output_parent):
    # WSL's virtual filesystem capacity does not describe free space on the
    # Windows volume containing its VHD. Run this collector on isolated Linux CI.
    if platform.system() != "Linux" or "microsoft" in platform.release().lower():
        raise RuntimeError("Image collection requires isolated native Linux")
    for path in (Path(tempfile.gettempdir()), output_parent):
        if shutil.disk_usage(path).free < MINIMUM_FREE_BYTES:
            raise RuntimeError("Image collection requires at least 6 GiB free space")


def sha_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def document(path, limit=8 * 1024 * 1024):
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    return bounded_json_object(raw, max_bytes=limit, max_nodes=200000)


def normalized(name):
    if type(name) is not str or not name or len(name) > 512:
        raise ValueError("Explicit package name required")
    return re.sub(r"[-_.]+", "-", name).lower()


def timestamp(value):
    if type(value) is not str:
        raise ValueError("Explicit scanner timestamp required")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None or result.utcoffset() != timedelta(0):
        raise ValueError("UTC scanner timestamp required")
    return result


def debian_package_version(entry):
    # Trivy 0.76 stores binary epoch/upstream/revision in separate fields.
    # SrcVersion/SrcRelease describe a different source package, not the
    # installed binary. In particular, preserve the binary rebuild (+bN).
    epoch, version, release = entry.get("Epoch", 0), entry.get("Version"), entry.get("Release", "")
    if type(epoch) is not int or not 0 <= epoch <= 2147483647:
        raise ValueError("Typed Debian binary epoch required")
    if type(version) is not str or not version or type(release) is not str:
        raise ValueError("Typed Debian binary version required")
    result = (str(epoch) + ":" if epoch else "") + version + ("-" + release if release else "")
    if len(result) > 1024 or not result.isascii() or any(c.isspace() for c in result):
        raise ValueError("Bounded Debian binary version required")
    return result


def assess(report, database, inventory, *, image_id, commit, started_at, finished_at):
    """Structural diagnostic projection of a caller-authenticated invocation."""
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Exact local image and source identifiers required")
    if (type(report.get("SchemaVersion")) is not int or report["SchemaVersion"] != 2
            or report.get("ArtifactType") != "container_image" or report.get("Trivy", {}).get("Version") != TRIVY_VERSION
            or report.get("Metadata", {}).get("ImageID") != image_id or inventory.get("commit_sha") != commit):
        raise ValueError("Image, scanner and source identity must agree")
    if not started_at <= timestamp(report.get("CreatedAt")) <= finished_at:
        raise ValueError("Report does not belong to the current invocation")
    updated = timestamp(database.get("UpdatedAt"))
    if type(database.get("Version")) is not int or database["Version"] != 2 or not timedelta(0) <= finished_at - updated <= timedelta(hours=24):
        raise ValueError("Current versioned vulnerability database required")
    if not started_at <= timestamp(database.get("DownloadedAt")) <= finished_at:
        raise ValueError("Fresh isolated vulnerability database download required")
    os_info = report["Metadata"].get("OS", {})
    family = os_info.get("Family")
    target_platform = inventory.get("platform", "linux/amd64")
    if target_platform not in {"linux/amd64", "linux/arm64"}:
        raise ValueError("Qualified image platform required")
    config = report["Metadata"].get("ImageConfig", {})
    if config.get("os", "") + "/" + config.get("architecture", "") != target_platform:
        raise ValueError("Scanner image architecture differs from runtime inventory")
    arm = target_platform == "linux/arm64"
    supported = {"debian": (r"13(?:\.[0-9]+)?", {"arm64" if arm else "amd64", "all"}),
                 "alpine": (r"3\.24(?:\.[0-9]+)?", {"aarch64" if arm else "x86_64", "noarch"})}
    if family not in supported or not re.fullmatch(supported[family][0], os_info.get("Name", "")):
        raise ValueError("Qualified OS release coverage required")
    if family == "alpine" and inventory.get("os_family") != family:
        raise ValueError("Explicit Alpine runtime inventory required")
    if inventory.get("os_family", family) != family:
        raise ValueError("Runtime and scanner OS families disagree")
    results = report.get("Results")
    if type(results) is not list or not results or len(results) > 512 or report.get("Errors"):
        raise ValueError("Explicit successful scanner result coverage required")
    installed = inventory.get("dependencies")
    if type(installed) is not list or not installed or len(installed) > 256:
        raise ValueError("Verified runtime Python inventory required")
    expected = set()
    for pair in installed:
        if type(pair) not in {list, tuple} or len(pair) != 2 or type(pair[1]) is not str or not pair[1]:
            raise ValueError("Typed installed Python package required")
        expected.add((normalized(pair[0]), pair[1]))
    installed_os = inventory.get("os_packages")
    if type(installed_os) is not list or not 1 <= len(installed_os) <= 4096:
        raise ValueError("Verified runtime OS inventory required")
    expected_os = set()
    for item in installed_os:
        if type(item) not in {list, tuple} or len(item) != 3 or any(type(x) is not str or not x for x in item):
            raise ValueError("Typed installed OS package identity required")
        if item[2] not in supported[family][1]:
            raise ValueError("Qualified OS package architecture required")
        expected_os.add(tuple(item))
    if len(expected_os) != len(installed_os) or inventory.get("package_installers_absent") is not True or inventory.get("global_python_packages") != []:
        raise ValueError("Unique OS inventory and absent global installers required")
    detected, detected_os, counts, packages = set(), set(), Counter(), Counter()
    findings = []
    for result in results:
        if type(result) is not dict or result.get("Class") not in {"os-pkgs", "lang-pkgs"} or result.get("ExperimentalModifiedFindings"):
            raise ValueError("Unfiltered OS/library result required")
        entries = result.get("Packages")
        if type(entries) is not list or not entries:
            raise ValueError("Explicit all-package inventory required")
        category = (result["Class"], result.get("Type"))
        packages[category] += len(entries)
        for entry in entries:
            if type(entry) is not dict or type(entry.get("Version")) is not str or not entry["Version"]:
                raise ValueError("Known installed package version required")
            name = normalized(entry.get("Name"))
            if category == ("lang-pkgs", "python-pkg"):
                detected.add((name, entry["Version"]))
            elif category == ("os-pkgs", family):
                detected_os.add((entry["Name"], debian_package_version(entry), entry.get("Arch")))
            else:
                raise ValueError("Unqualified package category cannot be ignored")
        vulnerabilities = result.get("Vulnerabilities", [])
        if type(vulnerabilities) is not list:
            raise ValueError("Typed scanner findings required")
        for finding in vulnerabilities:
            if type(finding) is not dict or any(type(finding.get(k)) is not str or not finding[k]
                for k in ("VulnerabilityID", "PkgName", "InstalledVersion", "Severity")):
                raise ValueError("Explicit vulnerability identity required")
            level = finding["Severity"]
            if level not in LEVELS:
                raise ValueError("Known scanner severity required")
            counts[level] += 1
            if level in {"HIGH", "CRITICAL", "UNKNOWN"}:
                findings.append({key: finding.get(key) for key in
                                 ("VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "Status")})
    if not packages[("os-pkgs", family)] or expected != detected or expected_os != detected_os:
        raise ValueError("Scanner coverage differs from the actual OS or Python inventory")
    gate = "BLOCK" if counts["HIGH"] or counts["CRITICAL"] or os_info.get("EOSL") else "UNKNOWN" if counts["UNKNOWN"] else "PASS"
    return dict(schema_version=1, policy="service-image-high-critical.v4", gate=gate, os_family=family, platform=target_platform,
                source_commit=commit, local_image_config_id=image_id, registry_digest=None,
                scanner_version=TRIVY_VERSION, database_updated_at=updated.isoformat(), observed_at=finished_at.isoformat(),
                severity_counts={key: counts[key] for key in sorted(LEVELS)}, os_package_count=packages[("os-pkgs", family)],
                os_packages_verified=len(expected_os),
                runtime_python_packages_verified=len(expected), blocking_or_unknown_findings=findings,
                execution_authorized=False, release_authorized=False, signed_attestation=False)


def scanner_command(*, image_id, trivy, inputs, cache, results, uid, gid, network, arguments):
    """Run the pinned scanner without the host checkout, credentials or Docker socket."""
    if network not in {"none", "bridge"} or uid <= 0 or gid <= 0:
        raise ValueError("Non-root isolated scanner identity required")
    mounts = [(trivy, "/scan-tool", True), (inputs, "/scan-input", True),
              (cache, "/scan-cache", False), (results, "/scan-output", False)]
    if any(not path.is_absolute() or "," in str(path) for path, _, _ in mounts):
        raise ValueError("Explicit safe scanner mount paths required")
    command = ["docker", "run", "--rm", "--pull=never", "--read-only", "--cap-drop=ALL",
               "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=2g", "--cpus=2",
               "--user", f"{uid}:{gid}", "--network=" + network,
               "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m", "--workdir=/tmp", "--env=HOME=/tmp",
               "--entrypoint=/scan-tool"]
    for path, target, readonly in mounts:
        command.extend(["--mount", f"type=bind,src={path},dst={target}" + (",readonly" if readonly else "")])
    return command + [image_id, "--cache-dir", "/scan-cache", "--config", "/scan-input/config.yaml", *arguments]


def scanner_file(root, relative, limit):
    """Do not let scanner-created symlinks turn artifact collection into a host read."""
    root = root.resolve(strict=True)
    path = root / relative
    if (not Path(relative).parts or Path(relative).is_absolute() or not path.is_relative_to(root)
            or any(part == ".." for part in Path(relative).parts)):
        raise ValueError("Scanner artifact escapes its owned directory")
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("Scanner artifact symlinks are forbidden")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= limit:
        raise ValueError("Bounded regular scanner artifact required")
    return path


def collect(*, trivy, image_id, commit, inventory_path, output):
    require_scan_capacity(output.parent)
    scanner_digest = {"x86_64": TRIVY_SHA256, "aarch64": TRIVY_ARM64_SHA256}.get(platform.machine())
    if scanner_digest is None or sha_file(trivy) != scanner_digest:
        raise ValueError("Qualified scanner executable required")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Exact local image and source identifiers required")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    started = datetime.now(UTC)
    with tempfile.TemporaryDirectory(prefix="sova-public-image-scan-") as temporary:
        work = Path(temporary)
        inputs, cache, results = (work / name for name in ("inputs", "cache", "results"))
        for directory in (inputs, cache, results):
            directory.mkdir(mode=0o700)
        (inputs / "config.yaml").write_text("{}\n")
        (inputs / "ignore").write_text("")
        environment = {"PATH": os.environ["PATH"], "HOME": str(work), "LANG": "C.UTF-8"}
        def run(args, *, stage, timeout=360):
            result = subprocess.run(args, cwd=work, env=environment, capture_output=True, timeout=timeout, check=False)
            if result.returncode:
                raise RuntimeError("Public image scan failed at " + stage)
            return result.stdout
        inspected = json.loads(run(["docker", "image", "inspect", image_id], stage="image inspection", timeout=20))
        if len(inspected) != 1 or inspected[0].get("Id") != image_id or inspected[0].get("Config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != commit:
            raise ValueError("Local image differs from the requested source commit")
        inventory = document(inventory_path, 65536)
        if inventory.get("platform") != inspected[0].get("Os", "") + "/" + inspected[0].get("Architecture", ""):
            raise ValueError("Runtime inventory differs from actual image architecture")
        run(["docker", "image", "save", "--output", str(inputs / "image.tar"), image_id],
            stage="owned image archive", timeout=120)
        def scan(arguments, *, stage, network="none", timeout=360):
            return run(scanner_command(image_id=image_id, trivy=trivy, inputs=inputs, cache=cache, results=results,
                                       uid=os.getuid(), gid=os.getgid(), network=network, arguments=arguments),
                       stage=stage, timeout=timeout)
        raw = scan(["--version", "--format", "json"], stage="scanner version", timeout=30)
        if json.loads(raw).get("Version") != TRIVY_VERSION:
            raise ValueError("Scanner version mismatch")
        (output / "scanner-version.json").write_bytes(raw)
        scan(["image", "--download-db-only", "--skip-version-check", "--quiet"],
             stage="isolated public database download", network="bridge")
        scan(["image", "--input", "/scan-input/image.tar", "--scanners", "vuln", "--pkg-types", "os,library",
              "--list-all-pkgs", "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", "--ignorefile", "/scan-input/ignore",
              "--offline-scan", "--skip-db-update", "--skip-version-check", "--timeout", "5m", "--format", "json", "--quiet",
              "--output", "/scan-output/scan.json"], stage="offline archive vulnerability collection")
        scan(["convert", "--format", "cyclonedx", "--output", "/scan-output/sbom.cdx.json", "/scan-output/scan.json"],
             stage="offline SBOM conversion", timeout=60)
        metadata_raw = scanner_file(cache, "db/metadata.json", 16384).read_bytes()
        (output / "database-metadata.json").write_bytes(metadata_raw)
        for name, limit in (("scan.json", 8 * 1024 ** 2), ("sbom.cdx.json", 16 * 1024 ** 2)):
            shutil.copyfile(scanner_file(results, name, limit), output / name)
        finished = datetime.now(UTC)
        result = assess(document(output / "scan.json"), document(output / "database-metadata.json", 16384), document(inventory_path, 65536),
                        image_id=image_id, commit=commit, started_at=started, finished_at=finished)
        result.update(scanner_binary_sha256=scanner_digest, database_sha256=sha_file(scanner_file(cache, "db/trivy.db", 1024 ** 3)),
                      report_sha256=sha_file(output / "scan.json"), runtime_inventory_sha256=sha_file(inventory_path),
                      scanner_isolation="nonroot-container-offline-archive.v1", scanner_docker_socket=False,
                      scan_network="none", database_download_network="bridge",
                      scanned_archive_sha256=sha_file(inputs / "image.tar"))
        result["sbom_sha256"] = sha_file(output / "sbom.cdx.json")
        (output / "decision.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("gate", "severity_counts", "os_package_count", "runtime_python_packages_verified", "release_authorized")}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trivy", type=Path, required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--runtime-inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        collect(trivy=args.trivy.resolve(strict=True), image_id=args.image_id, commit=args.commit,
                inventory_path=args.runtime_inventory.resolve(strict=True), output=args.output.absolute())
    except (ValueError, RuntimeError) as error:
        # Only our fixed diagnostic messages; never echo subprocess output.
        parser.exit(2, f"Service image evidence unavailable: {error}. Qualification remains UNKNOWN.\n")
    except Exception:
        parser.exit(2, "Service image evidence unavailable; qualification remains UNKNOWN.\n")


if __name__ == "__main__":
    main()
