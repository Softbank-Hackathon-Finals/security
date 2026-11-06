"""Create an exclusive, public-only build context from a clean Git revision.

Run with the locked development Python environment and uv 0.13.6. This does
not build/publish an image, sign an attestation, or read deployment credentials.
"""

import argparse
from email.parser import BytesParser
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import tomllib
import zipfile


BASE = "python:3.12.16-slim-trixie@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54"
UV_VERSION = "0.13.6"


def run(command, *, cwd):
    result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        # Build tools can include environment-specific paths/index credentials in errors.
        raise RuntimeError(f"Build preparation command failed: {Path(command[0]).name}; exit={result.returncode}")
    return result.stdout


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(project, output, uv):
    project = project.resolve(strict=True)
    output = output.absolute()
    git = ["git", "-c", "safe.directory=" + str(project)]
    if Path(run(git + ["rev-parse", "--show-toplevel"], cwd=project).decode().strip()).resolve() != project:
        raise ValueError("Project must be the repository root")
    if run(git + ["status", "--porcelain", "--untracked-files=normal"], cwd=project):
        raise ValueError("Build preparation requires a clean committed source tree")
    revision = run(git + ["rev-parse", "HEAD"], cwd=project).decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("An exact Git revision is required")
    if run([uv, "--version"], cwd=project).decode().strip().split()[:2] != ["uv", UV_VERSION]:
        raise ValueError("Use the qualified uv version")
    if output.exists() or output.is_symlink():
        raise ValueError("Output must be a new directory; existing data is never replaced")
    archive_bytes = run(git + ["archive", "--format=zip", revision], cwd=project)
    with tempfile.TemporaryDirectory(prefix="sova-service-build-") as temporary:
        source = Path(temporary) / "source"
        source.mkdir()
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            for item in archive.infolist():
                relative = PurePosixPath(item.filename)
                if relative.is_absolute() or ".." in relative.parts or "\\" in item.filename:
                    raise ValueError("Unsafe source archive member")
                if (item.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("Source archive symlinks are not supported")
                target = source.joinpath(*relative.parts)
                if item.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.read(item))
        metadata = tomllib.loads((source / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        if metadata["name"] != "sova-security":
            raise ValueError("Unexpected package")
        template = source / "deploy/security-review.Dockerfile"
        if template.read_text(encoding="utf-8").count("FROM " + BASE) != 2:
            raise ValueError("Both build stages must use the qualified base digest")
        requirements = run([uv, "export", "--locked", "--offline", "--no-default-groups", "--extra", "service",
                            "--no-emit-project", "--no-header", "--no-annotate", "--python", sys.executable], cwd=source)
        # Only exact registry requirements, markers, continuations and sha256 hashes.
        entries = requirements.decode("utf-8").replace("\\\n", " ").splitlines()
        if not entries or any(not re.fullmatch(r"[A-Za-z0-9_.-]+==[^\s;]+(?:\s*;[^\n]+)?\s+--hash=sha256:[0-9a-f]{64}(?:\s+--hash=sha256:[0-9a-f]{64})*\s*", line)
                              for line in entries if line.strip()):
            raise ValueError("Only hashed, exact registry requirements are supported")
        wheels = Path(temporary) / "dist"
        wheels.mkdir()
        run([sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "--no-build-isolation", "--no-index", "-w", str(wheels)], cwd=source)
        files = list(wheels.iterdir())
        if len(files) != 1 or not re.fullmatch(r"sova_security-[0-9][A-Za-z0-9_.]*-py3-none-any\.whl", files[0].name):
            raise ValueError("Expected exactly one portable service wheel")
        wheel = files[0]
        with zipfile.ZipFile(wheel) as archive:
            names = [p for p in archive.namelist() if p.endswith(".dist-info/METADATA")]
            if len(names) != 1:
                raise ValueError("Ambiguous wheel metadata")
            built = BytesParser().parsebytes(archive.read(names[0]))
        if built["Name"] != metadata["name"] or built["Version"] != metadata["version"]:
            raise ValueError("Wheel does not match committed project metadata")
        if run(git + ["rev-parse", "HEAD"], cwd=project).decode().strip() != revision or run(
            git + ["status", "--porcelain", "--untracked-files=normal"], cwd=project
        ):
            raise ValueError("Source changed during preparation")
        manifest = dict(schema_version=1, repository="Softbank-Hackathon-Finals/security", commit_sha=revision,
                        package=metadata["name"], version=metadata["version"], platform="linux/amd64", base=BASE,
                        uv_version=UV_VERSION, lock_sha256=sha(source / "uv.lock"), wheel=wheel.name,
                        wheel_sha256=sha(wheel), requirements_sha256=hashlib.sha256(requirements).hexdigest(),
                        dockerfile_sha256=sha(template), preparation_sha256=sha(source / "scripts/prepare_service_image.py"),
                        execution_authorized=False, signed_attestation=False)
        output.mkdir(parents=True, exist_ok=False)
        (output / "dist").mkdir()
        (output / "dist" / wheel.name).write_bytes(wheel.read_bytes())
        (output / "requirements.txt").write_bytes(requirements)
        (output / "Dockerfile").write_bytes(template.read_bytes())
        (output / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"commit_sha": revision, "wheel_sha256": manifest["wheel_sha256"], "output": str(output)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--uv", default="uv")
    args = parser.parse_args()
    prepare(args.project, args.output, args.uv)


if __name__ == "__main__":
    main()
