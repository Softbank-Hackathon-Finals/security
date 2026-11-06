"""Scanner evidence must cover the exact local image and installed environment."""

from copy import deepcopy
from datetime import timedelta
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


spec = importlib.util.spec_from_file_location("service_image_scan", Path(__file__).resolve().parents[2] / "scripts" / "scan_service_image.py")
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)
IMAGE, COMMIT = "sha256:" + "a" * 64, "b" * 40


def fixture(now):
    report = dict(SchemaVersion=2, ArtifactType="container_image", Trivy={"Version": "0.76.2"}, CreatedAt=now.isoformat(),
                  Metadata=dict(ImageID=IMAGE, OS=dict(Family="debian", Name="13", EOSL=False)),
                  Results=[dict(Class="os-pkgs", Type="debian", Packages=[dict(Name="libc6", Version="2.41", Arch="amd64")]),
                           dict(Class="lang-pkgs", Type="python-pkg", Packages=[dict(Name="sova_security", Version="0.11.0"),
                                                                                dict(Name="uvicorn", Version="0.54.0")])])
    database = dict(Version=2, UpdatedAt=(now - timedelta(hours=1)).isoformat(), DownloadedAt=now.isoformat())
    inventory = dict(commit_sha=COMMIT, dependencies=[["sova-security", "0.11.0"], ["uvicorn", "0.54.0"]],
                     os_packages=[["libc6", "2.41", "amd64"]], package_installers_absent=True, global_python_packages=[])
    return report, database, inventory


def assess(values, now):
    return scanner.assess(*values, image_id=IMAGE, commit=COMMIT, started_at=now - timedelta(seconds=1), finished_at=now + timedelta(seconds=1))


@pytest.mark.parametrize("level,expected", [(None, "PASS"), ("LOW", "PASS"), ("MEDIUM", "PASS"),
                                           ("HIGH", "BLOCK"), ("CRITICAL", "BLOCK"), ("UNKNOWN", "UNKNOWN")])
def test_scan_policy_is_explicit_and_never_a_release_capability(now, level, expected):
    values = fixture(now)
    if level:
        values[0]["Results"][0]["Vulnerabilities"] = [dict(VulnerabilityID="CVE-2026-12345", PkgName="libc6",
            InstalledVersion="2.41", Severity=level, Status="will_not_fix")]
    result = assess(values, now)
    assert result["gate"] == expected  # Unfixed HIGH/CRITICAL findings still block.
    assert result["registry_digest"] is None and result["local_image_config_id"] == IMAGE
    assert result["runtime_python_packages_verified"] == 2
    assert result["execution_authorized"] is result["release_authorized"] is result["signed_attestation"] is False


@pytest.mark.parametrize("fault", ["image", "source", "tool", "stale-report", "future-report", "stale-db", "future-db",
                                  "old-cache", "missing-os", "missing-python", "wrong-python-version", "filtered", "error", "no-packages"])
def test_missing_stale_filtered_or_wrong_artifacts_cannot_be_clean(now, fault):
    values = deepcopy(fixture(now))
    report, database, inventory = values
    if fault == "image":
        report["Metadata"]["ImageID"] = "sha256:" + "c" * 64
    elif fault == "source":
        inventory["commit_sha"] = "c" * 40
    elif fault == "tool":
        report["Trivy"]["Version"] = "0.1"
    elif fault in {"stale-report", "future-report"}:
        report["CreatedAt"] = (now + timedelta(days=1 if fault == "future-report" else -1)).isoformat()
    elif fault in {"stale-db", "future-db"}:
        database["UpdatedAt"] = (now + timedelta(days=2 if fault == "future-db" else -2)).isoformat()
    elif fault == "old-cache":
        database["DownloadedAt"] = (now - timedelta(hours=2)).isoformat()
    elif fault == "missing-os":
        report["Results"].pop(0)
    elif fault == "missing-python":
        report["Results"].pop()
    elif fault == "wrong-python-version":
        report["Results"][1]["Packages"][0]["Version"] = "0.10.0"
    elif fault == "filtered":
        report["Results"][0]["ExperimentalModifiedFindings"] = [{"Status": "not_affected"}]
    elif fault == "error":
        report["Errors"] = ["partial collector failure"]
    else:
        report["Results"][0].pop("Packages")
    with pytest.raises(ValueError):
        assess(values, now)


def test_end_of_life_os_blocks_even_without_reported_findings(now):
    values = fixture(now)
    values[0]["Metadata"]["OS"]["EOSL"] = True
    assert assess(values, now)["gate"] == "BLOCK"


@pytest.mark.parametrize("fault", ["missing-inventory", "extra-installed-package", "wrong-version", "wrong-architecture",
                                  "duplicate-inventory", "unknown-global-package", "unexpected-scanner-package"])
def test_scan_must_cover_exact_actual_os_and_python_inventory(now, fault):
    values = fixture(now)
    report, _, inventory = values
    if fault == "missing-inventory":
        inventory.pop("os_packages")
    elif fault == "extra-installed-package":
        inventory["os_packages"].append(["unscanned-library", "1.0", "amd64"])
    elif fault == "wrong-version":
        report["Results"][0]["Packages"][0]["Version"] = "2.40"
    elif fault == "wrong-architecture":
        report["Results"][0]["Packages"][0]["Arch"] = "arm64"
    elif fault == "duplicate-inventory":
        inventory["os_packages"] *= 2
    elif fault == "unknown-global-package":
        inventory["global_python_packages"] = [["pip", "25.0.1"]]
    else:
        report["Results"][1]["Packages"].append(dict(Name="pip", Version="25.0.1"))
    with pytest.raises(ValueError):
        assess(values, now)


@pytest.mark.parametrize("system,release,free,allowed", [
    ("Linux", "6.8.0", 6 * 1024 ** 3, True),
    ("Linux", "6.8.0", 6 * 1024 ** 3 - 1, False),
    ("Linux", "6.6.0-microsoft-standard-WSL2", 900 * 1024 ** 3, False),
    ("Windows", "10", 10 * 1024 ** 3, False),
])
def test_collection_capacity_rejects_low_space_and_virtual_host_capacity(monkeypatch, tmp_path, system, release, free, allowed):
    monkeypatch.setattr(scanner.platform, "system", lambda: system)
    monkeypatch.setattr(scanner.platform, "release", lambda: release)
    monkeypatch.setattr(scanner.shutil, "disk_usage", lambda path: SimpleNamespace(free=free))
    if allowed:
        scanner.require_scan_capacity(tmp_path)
    else:
        with pytest.raises(RuntimeError):
            scanner.require_scan_capacity(tmp_path)
