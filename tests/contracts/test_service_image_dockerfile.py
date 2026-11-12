"""The service image template changes OS packages only to exact versions."""

from pathlib import Path
import re


DOCKERFILE = Path(__file__).resolve().parents[2] / "deploy" / "security-review.Dockerfile"


def runtime_stage():
    text = DOCKERFILE.read_text(encoding="utf-8")
    stages = re.split(r"^FROM ", text, flags=re.M)
    # The final stage is what ships; the build stage never reaches the runtime image.
    return " ".join(line.strip() for line in stages[-1].splitlines() if not line.lstrip().startswith("#"))


def test_runtime_os_package_changes_are_exact_pins():
    commands = re.findall(r"\bapk\s+([a-z]+)([^&;]*)", runtime_stage())
    assert commands, "the runtime stage is expected to patch an OS package"
    for verb, arguments in commands:
        assert verb == "add", "only exact `apk add pkg=version` is allowed, not " + verb
        assert "--no-cache" in arguments, "apk must not leave an index cache in the image"
        packages = [token.strip("'\"\\") for token in arguments.split() if not token.startswith("-")]
        packages = [token for token in packages if token]
        assert packages, "apk add must name its packages"
        for package in packages:
            assert re.fullmatch(r"[a-z0-9][a-z0-9+._-]*=[0-9][0-9A-Za-z._+~-]*-r[0-9]+", package), (
                "OS package must be pinned to an exact Alpine release: " + package
            )


def test_krb5_libs_is_the_fixed_release():
    assert "krb5-libs=1.22.3-r0" in runtime_stage()
