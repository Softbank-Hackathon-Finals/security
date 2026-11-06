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
import subprocess
import tempfile

from sova_security.adapters.bounded_json import bounded_json_object

TRIVY_VERSION = "0.76.2"
TRIVY_SHA256 = "6a972c69606c7b3ea4c6bdcc6fc9332ea9ad38381624310c1e85cc77345909f3"
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
    if os_info.get("Family") != "debian" or not re.fullmatch(r"13(?:\.[0-9]+)?", os_info.get("Name", "")):
        raise ValueError("Expected Debian 13 image coverage required")
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
    detected, counts, packages = set(), Counter(), Counter()
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
    if not packages[("os-pkgs", "debian")] or not expected <= detected:
        raise ValueError("Operating system or installed service package coverage is missing")
    gate = "BLOCK" if counts["HIGH"] or counts["CRITICAL"] or os_info.get("EOSL") else "UNKNOWN" if counts["UNKNOWN"] else "PASS"
    return dict(schema_version=1, policy="service-image-high-critical.v1", gate=gate,
                source_commit=commit, local_image_config_id=image_id, registry_digest=None,
                scanner_version=TRIVY_VERSION, database_updated_at=updated.isoformat(), observed_at=finished_at.isoformat(),
                severity_counts={key: counts[key] for key in sorted(LEVELS)}, os_package_count=packages[("os-pkgs", "debian")],
                runtime_python_packages_verified=len(expected), blocking_or_unknown_findings=findings,
                execution_authorized=False, release_authorized=False, signed_attestation=False)


def collect(*, trivy, image_id, commit, inventory_path, output):
    require_scan_capacity(output.parent)
    if sha_file(trivy) != TRIVY_SHA256:
        raise ValueError("Qualified scanner executable required")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Exact local image and source identifiers required")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    started = datetime.now(UTC)
    with tempfile.TemporaryDirectory(prefix="sova-public-image-scan-") as temporary:
        work = Path(temporary)
        (work / "config.yaml").write_text("{}\n")
        (work / "ignore").write_text("")
        environment = {"PATH": os.environ["PATH"], "HOME": str(work), "LANG": "C.UTF-8"}
        def run(args, *, stage, timeout=360):
            result = subprocess.run(args, cwd=work, env=environment, capture_output=True, timeout=timeout, check=False)
            if result.returncode:
                raise RuntimeError("Public image scan failed at " + stage)
            return result.stdout
        inspected = json.loads(run(["docker", "image", "inspect", image_id], stage="image inspection", timeout=20))
        if len(inspected) != 1 or inspected[0].get("Id") != image_id or inspected[0].get("Config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != commit:
            raise ValueError("Local image differs from the requested source commit")
        common = [str(trivy), "--cache-dir", str(work / "cache"), "--config", str(work / "config.yaml")]
        raw = run(common + ["--version", "--format", "json"], stage="scanner version", timeout=10)
        if json.loads(raw).get("Version") != TRIVY_VERSION:
            raise ValueError("Scanner version mismatch")
        (output / "scanner-version.json").write_bytes(raw)
        run(common + ["image", "--image-src", "docker", "--scanners", "vuln", "--pkg-types", "os,library",
            "--list-all-pkgs", "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", "--ignorefile", str(work / "ignore"),
            "--offline-scan", "--skip-version-check", "--timeout", "5m", "--format", "json", "--quiet",
            "--output", str(output / "scan.json"), image_id], stage="vulnerability collection")
        db = work / "cache" / "db"
        metadata_raw = (db / "metadata.json").read_bytes()
        (output / "database-metadata.json").write_bytes(metadata_raw)
        finished = datetime.now(UTC)
        result = assess(document(output / "scan.json"), document(output / "database-metadata.json", 16384), document(inventory_path, 65536),
                        image_id=image_id, commit=commit, started_at=started, finished_at=finished)
        result.update(scanner_binary_sha256=TRIVY_SHA256, database_sha256=sha_file(db / "trivy.db"),
                      report_sha256=sha_file(output / "scan.json"), runtime_inventory_sha256=sha_file(inventory_path))
        run(common + ["convert", "--format", "cyclonedx", "--output", str(output / "sbom.cdx.json"), str(output / "scan.json")], stage="SBOM conversion", timeout=30)
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
