"""Opt-in real PG/TLS process endurance; issuer and measurements are synthetic."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import time
from uuid import uuid4

import pytest

from test_postgres_boundary import database as isolated_database
from review_runtime_support import registered_review_runtime
from review_service_support import service_bundle
from sova_security.adapters.modernization_codec import decode, encode
from sova_security.adapters.review_https import BearerCredential, ReviewTransportError

database = isolated_database
pytestmark = pytest.mark.postgres


def atomic_mount(path, raw):
    staging = path.with_name(path.name + ".next")
    with staging.open("xb") as stream:
        os.chmod(staging, 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(staging, path)


def children():
    return set((Path("/proc/self/task") / str(os.getpid()) / "children").read_text().split())


def resources(pid):
    status = dict(line.split(":", 1) for line in (Path("/proc") / pid / "status").read_text().splitlines())
    return dict(rss_kib=int(status["VmRSS"].split()[0]), threads=int(status["Threads"]),
                descriptors=len(list((Path("/proc") / pid / "fd").iterdir())))


def test_live_process_rotation_expiry_revocation_and_resources(database, scope, tmp_path):
    configured = os.environ.get("SOVA_REVIEW_ENDURANCE_SECONDS")
    if configured is None:
        pytest.skip("Explicit 180..14400 second owned-process endurance run required")
    seconds = int(configured)
    assert 180 <= seconds <= 14400 and Path("/proc/self/status").is_file()
    assert not os.environ.get("SOVA_TEST_REVIEW_IMAGE"), "Process PID/resource qualification only"
    report = Path(os.environ["SOVA_REVIEW_ENDURANCE_REPORT"])
    assert report.is_absolute() and report.parent.is_dir()
    with report.open("x") as stream:
        os.chmod(report, 0o600)
        stream.write("{}")
    now = datetime.now(UTC)
    scope = replace(scope, application_id="endurance-" + uuid4().hex)
    state, _, request = service_bundle(scope, now)
    end = now + timedelta(seconds=seconds + 180)
    # Long-lived *synthetic* evidence is fixed before startup and is never
    # refreshed by review. Only short-lived client/reviewer credentials rotate.
    program = replace(state.registration.program, valid_until=end)
    registration = replace(state.registration, program=program, valid_until=end)
    evidence = tuple(replace(item, valid_until=end) for item in state.evidence)
    principal = replace(state.principal, valid_until=end)
    request = replace(request, context_digest=registration.fingerprint)
    progress = dict(status="starting", started_at=now.isoformat(), requested_seconds=seconds,
                    cycles=0, accepted=0, revoked_denials=0, grant_denials=0, expired_denials=0,
                    credential_rotations=0, execution_authorized=False,
                    evidence_source="synthetic signed originals", identity_source="local issuer simulator")
    source = Path(__file__).resolve().parents[2] / "src" / "sova_security"
    progress["source_files_sha256"] = {str(path.relative_to(source)): hashlib.sha256(path.read_bytes()).hexdigest()
                                       for path in sorted(source.rglob("*.py"))}
    progress["test_file_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def record():
        progress["observed_at"] = datetime.now(UTC).isoformat()
        atomic_mount(report, (json.dumps(progress, sort_keys=True, indent=2) + "\n").encode())

    before = children()
    try:
        with registered_review_runtime(database, tmp_path, registration=registration, evidence=evidence,
                                       principal=principal, now=now) as runtime:
            owned = children() - before
            assert len(owned) == 1, "Expected one owned service child"
            pid = owned.pop()
            command = (Path("/proc") / pid / "cmdline").read_bytes().split(b"\0")
            assert b"sova_security.interfaces.review_server" in command
            grants = (tmp_path / "grants.json").read_bytes()
            expired_candidate = runtime.credential
            credential = runtime.credential
            baseline = None
            started = time.monotonic()
            progress.update(status="running", pid=int(pid))

            def invoke(selected, *, denied=False):
                runtime.issuer.now = datetime.now(UTC)
                current = replace(request, request_id=hashlib.sha256(uuid4().bytes).hexdigest())
                if denied:
                    with pytest.raises(ReviewTransportError):
                        runtime.transport.post("/v1/program-reviews", encode(current).encode(), selected)
                    return
                result = decode(runtime.transport.post("/v1/program-reviews", encode(current).encode(), selected))
                assert result.review.passed and result.execution_authorized is False
                assert result.request_id == current.request_id and result.valid_until <= datetime.now(UTC) + timedelta(seconds=5)
                progress["accepted"] += 1

            while time.monotonic() - started < seconds:
                cycle_start = time.monotonic()
                runtime.issuer.now = datetime.now(UTC)
                runtime.issuer.client_token = runtime.issuer.issue(runtime.issuer.username, runtime.issuer.audience)
                runtime.issuer.reviewer_token = runtime.issuer.issue("system:serviceaccount:security:reviewer", "api-server")
                credential = BearerCredential(runtime.issuer.client_token, runtime.issuer.now + timedelta(minutes=2))
                atomic_mount(tmp_path / "reviewer.token", runtime.issuer.reviewer_token.encode())
                progress["credential_rotations"] += 1
                invoke(credential)
                runtime.issuer.active = False
                try:
                    invoke(credential, denied=True)
                    progress["revoked_denials"] += 1
                finally:
                    runtime.issuer.active = True
                atomic_mount(tmp_path / "grants.json", b'{"schema_version":1,"grants":[]}')
                try:
                    invoke(credential, denied=True)
                    progress["grant_denials"] += 1
                finally:
                    atomic_mount(tmp_path / "grants.json", grants)
                if datetime.now(UTC) > expired_candidate.valid_until + timedelta(seconds=1):
                    invoke(expired_candidate, denied=True)
                    progress["expired_denials"] += 1
                invoke(credential)
                sample = resources(pid)
                if baseline is None:
                    baseline = sample
                    progress["baseline_resources"] = baseline
                assert sample["descriptors"] <= baseline["descriptors"] + 12, "Service descriptors grew beyond bound"
                assert sample["rss_kib"] <= baseline["rss_kib"] + 65536, "Service RSS grew beyond bound"
                assert sample["threads"] <= baseline["threads"] + 16, "Service worker threads grew beyond bound"
                progress["last_resources"] = sample
                progress["max_resources"] = {key: max(value, progress.get("max_resources", {}).get(key, 0))
                                             for key, value in sample.items()}
                progress["cycles"] += 1
                progress["elapsed_seconds"] = round(time.monotonic() - started, 3)
                record()
                remaining = seconds - (time.monotonic() - started)
                if remaining > 0:
                    time.sleep(min(remaining, max(0, 30 - (time.monotonic() - cycle_start))))
            assert progress["expired_denials"] > 0, "Run did not cross actual credential expiry"
            audit = (tmp_path / "audit.jsonl").read_text()
            assert credential.token not in audit and expired_candidate.token not in audit
            progress.update(status="verifying-cleanup", elapsed_seconds=round(time.monotonic() - started, 3))
        assert not (Path("/proc") / pid).exists(), "Owned service did not exit"
        progress.update(status="completed", owned_process_stopped=True)
    finally:
        if progress["status"] != "completed":
            progress["status"] = "failed"
        record()
