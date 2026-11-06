"""Export the exact scanned image for handoff, without registry publication.

An archive checksum is not a publisher signature or a deployment capability.
Only a fresh PASS for this source/platform/config ID may produce an archive.
"""

import argparse
from datetime import UTC, datetime, timedelta
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess


def qualification(manifest, decision, inspected, now):
    source, image_id = manifest.get("commit_sha"), decision.get("local_image_config_id")
    if (type(source) is not str or not re.fullmatch(r"[0-9a-f]{40}", source)
            or type(image_id) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)):
        raise ValueError("Exact source and image identifiers required")
    if (decision.get("gate") != "PASS" or decision.get("policy") != "service-image-high-critical.v4"
            or decision.get("source_commit") != source or decision.get("platform") != manifest.get("platform")
            or manifest.get("platform") not in {"linux/amd64", "linux/arm64"}
            or any(type(decision.get("severity_counts", {}).get(level)) is not int
                   or decision["severity_counts"][level] != 0 for level in ("HIGH", "CRITICAL", "UNKNOWN"))):
        raise ValueError("Current matching PASS required before image export")
    observed = datetime.fromisoformat(decision["observed_at"])
    if observed.tzinfo is None or not timedelta(0) <= now - observed <= timedelta(minutes=30):
        raise ValueError("Fresh scan required before image export")
    if (type(inspected) is not list or len(inspected) != 1 or inspected[0].get("Id") != image_id
            or inspected[0].get("Os", "") + "/" + inspected[0].get("Architecture", "") != manifest["platform"]
            or inspected[0].get("Config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != source):
        raise ValueError("Export image does not match the scanned source/platform")
    return dict(schema_version=1, source_commit=source, platform=manifest["platform"],
        local_image_config_id=image_id, policy=decision["policy"], observed_at=decision["observed_at"],
        registry_digest=None, release_authorized=False, signed_attestation=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    context = args.context.resolve(strict=True)
    manifest = json.loads((context / "manifest.json").read_text())
    decision = json.loads((context / "scan/decision.json").read_text())
    image_id = (context / "local-image-id.txt").read_text().strip()
    if image_id != decision.get("local_image_config_id"):
        raise ValueError("Image identifier file differs from scanner evidence")
    raw = subprocess.check_output(["docker", "image", "inspect", image_id], timeout=20)
    evidence = qualification(manifest, decision, json.loads(raw), datetime.now(UTC))
    output = args.output.absolute()
    output.mkdir(parents=False, exist_ok=False)
    tar_path = output / "image.tar"
    subprocess.run(["docker", "image", "save", "--output", str(tar_path), image_id], check=True, timeout=120)
    compressed = output / "image.tar.gz"
    with tar_path.open("rb") as source, compressed.open("xb") as target:
        with gzip.GzipFile(filename="", mode="wb", fileobj=target, mtime=0) as stream:
            shutil.copyfileobj(source, stream, 1024 * 1024)
    tar_path.unlink()  # Only the exact temporary file created above.
    with compressed.open("rb") as stream:
        evidence["archive_sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
    evidence["archive_bytes"] = compressed.stat().st_size
    evidence["archive_format"] = "docker-save+gzip"
    evidence["archive"] = compressed.name
    evidence["scan_decision_sha256"] = hashlib.sha256((context / "scan/decision.json").read_bytes()).hexdigest()
    (output / "archive-provenance.json").write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
    print(json.dumps({key: evidence[key] for key in ("source_commit", "platform", "archive_sha256", "archive_bytes")}))


if __name__ == "__main__":
    main()
