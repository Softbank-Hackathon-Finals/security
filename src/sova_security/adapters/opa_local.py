"""Pinned local OPA, not an in-house Rego interpreter or a guest-code sandbox.

Operator policy only; no inherited credentials, network/runtime builtins, shell,
arbitrary query, unbounded output or unlimited evaluation. POSIX first profile.
"""

import hashlib
from importlib.resources import files
import os
from pathlib import Path
import selectors
import stat
import subprocess
import tempfile
import time

from sova_security.adapters.vulnerability_reports import bounded_report
from sova_security.contracts.commands import ContractError, canonical_json, digest
from sova_security.domain.opa_policy import OPAPolicy, OPA_QUERY, validate_verdict


def restricted_capabilities():
    return (
        files("sova_security")
        .joinpath("policies/restricted-capabilities.json")
        .read_bytes()
    )


def preflight_policy_source():
    return files("sova_security").joinpath("policies/preflight.rego").read_text()


class PinnedLocalOPA:
    def __init__(self, binary, *, expected_digest, timeout_seconds=3):
        digest(expected_digest)
        if (
            os.name != "posix"
            or type(timeout_seconds) is not int
            or not 1 <= timeout_seconds <= 10
        ):
            raise ContractError("Bounded POSIX OPA execution profile required")
        self.binary = Path(binary)
        if not self.binary.is_absolute():
            raise ContractError("Absolute registered OPA binary path required")
        self.expected_digest = expected_digest
        self.timeout_seconds = timeout_seconds

    def _verify_binary(self):
        try:
            info = self.binary.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid not in {0, os.getuid()}
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                raise ContractError(
                    "Operator-owned non-writable-by-others OPA binary required"
                )
            with self.binary.open("rb") as f:
                actual = hashlib.file_digest(f, "sha256").hexdigest()
        except OSError as exc:
            raise ContractError("Registered OPA binary unavailable") from exc
        if actual != self.expected_digest:
            raise ContractError("OPA binary digest changed")

    def evaluate(self, policy, input_document):
        if (
            not isinstance(policy, OPAPolicy)
            or policy.engine_digest != self.expected_digest
        ):
            raise ContractError("Registered OPA engine profile required")
        self._verify_binary()
        capabilities = restricted_capabilities()
        if hashlib.sha256(capabilities).hexdigest() != policy.capabilities_digest:
            raise ContractError(
                "Restricted OPA capabilities differ from registered policy"
            )
        body = canonical_json(input_document, limit=262144).encode()
        with tempfile.TemporaryDirectory(prefix="sova-opa-") as directory:
            root = Path(directory)
            for name, value in [
                ("policy.rego", policy.source.encode()),
                ("input.json", body),
                ("capabilities.json", capabilities),
            ]:
                path = root / name
                path.write_bytes(value)
                path.chmod(0o400)
            args = [
                str(self.binary),
                "eval",
                "--strict",
                "--strict-builtin-errors",
                "--fail",
                "--timeout",
                str(self.timeout_seconds) + "s",
                "--format",
                "json",
                "--capabilities",
                str(root / "capabilities.json"),
                "--data",
                str(root / "policy.rego"),
                "--input",
                str(root / "input.json"),
                OPA_QUERY,
            ]
            env = {"PATH": "/usr/bin:/bin", "TMPDIR": directory}
            process = subprocess.Popen(
                args,
                cwd=root,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            output = {"out": bytearray(), "err": bytearray()}
            try:
                with selectors.DefaultSelector() as selected:
                    selected.register(process.stdout, selectors.EVENT_READ, "out")
                    selected.register(process.stderr, selectors.EVENT_READ, "err")
                    end = time.monotonic() + self.timeout_seconds
                    while selected.get_map():
                        remaining = end - time.monotonic()
                        if remaining <= 0:
                            raise ContractError("OPA evaluation timed out")
                        for key, _ in selected.select(min(remaining, 0.1)):
                            chunk = os.read(key.fileobj.fileno(), 4096)
                            if not chunk:
                                selected.unregister(key.fileobj)
                                continue
                            output[key.data].extend(chunk)
                            limit = 65536 if key.data == "out" else 8192
                            if len(output[key.data]) > limit:
                                raise ContractError("OPA output limit exceeded")
                    if process.wait(timeout=max(0.01, end - time.monotonic())) != 0:
                        raise ContractError("OPA rejected policy or evaluation")
            except subprocess.TimeoutExpired as exc:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=2)
                raise ContractError("OPA evaluation timed out") from exc
            except BaseException:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=2)
                raise
            finally:
                process.stdout.close()
                process.stderr.close()
            data = bounded_report(bytes(output["out"]))
        if (
            type(data) is not dict
            or set(data) != {"result"}
            or type(data["result"]) is not list
            or len(data["result"]) != 1
        ):
            raise ContractError("OPA decision is undefined or ambiguous")
        if type(data["result"][0]) is not dict:
            raise ContractError("OPA result object required")
        expressions = data["result"][0].get("expressions")
        if (
            type(expressions) is not list
            or len(expressions) != 1
            or type(expressions[0]) is not dict
        ):
            raise ContractError("One OPA decision expression required")
        value = expressions[0].get("value")
        if (
            type(value) is not dict
            or set(value) != {"allow", "reasons"}
            or type(value["reasons"]) is not list
        ):
            raise ContractError("Strict OPA decision object required")
        validate_verdict(value["allow"], tuple(value["reasons"]))
        self._verify_binary()
        return value["allow"], tuple(value["reasons"])
