import base64
from dataclasses import asdict
from datetime import timedelta
import json
import os

import pytest

from review_service_support import service_bundle
from sova_security.adapters.review_mounts import LocalReviewAudit, MountedTokenCredential, MountedWorkloadGrants, mounted_bytes
from sova_security.contracts.commands import ContractError


def grant_document(state):
    p = state.principal
    return dict(schema_version=1, grants=[dict(username="system:serviceaccount:security:test-worker", uid="test-uid",
        subject_id=p.subject_id, tenant_id=p.tenant_id, scopes=[asdict(s) for s in p.scopes], modes=list(p.modes),
        issued_at=p.issued_at.isoformat(), valid_until=p.valid_until.isoformat())])


def test_mounted_grant_rotation_and_ambiguous_identity_fail_closed(scope, now, tmp_path):
    state, _, _ = service_bundle(scope, now)
    path = tmp_path / "grants.json"
    doc = grant_document(state)
    path.write_text(json.dumps(doc))
    lookup = MountedWorkloadGrants(path)
    original = lookup("system:serviceaccount:security:test-worker", "test-uid")
    assert original.principal.modes == ("enforce", "shadow")
    doc["grants"][0]["modes"] = ["shadow"]
    path.write_text(json.dumps(doc))
    assert lookup(original.username, original.uid).principal.grant_digest != original.principal.grant_digest
    assert lookup(original.username, "replacement-uid") is None
    doc["grants"].append(doc["grants"][0])
    path.write_text(json.dumps(doc))
    with pytest.raises(ContractError):
        lookup(original.username, original.uid)
    path.write_text('{"schema_version":1,"grants":[]}')
    assert lookup(original.username, original.uid) is None


def test_projected_token_rotation_and_expiry(now, tmp_path):
    path = tmp_path / "token"
    provider = MountedTokenCredential(path, clock=lambda: now)
    def token(exp):
        payload = base64.urlsafe_b64encode(json.dumps(dict(exp=exp)).encode()).rstrip(b"=").decode()
        return "test." + payload + ".signature"
    first = token(int((now + timedelta(seconds=60)).timestamp()))
    path.write_text(first)
    assert provider().token == first
    second = token(int((now + timedelta(seconds=30)).timestamp()))
    path.write_text(second)
    assert provider().token == second
    path.write_text(token(int(now.timestamp())))
    with pytest.raises(ContractError):
        provider()


def test_mount_bounds_and_local_audit(tmp_path):
    path = tmp_path / "mount"
    path.write_bytes(b"12345")
    assert mounted_bytes(path, limit=5) == b"12345"
    with pytest.raises(ContractError):
        mounted_bytes(path, limit=4)
    with pytest.raises(ContractError):
        mounted_bytes("relative", limit=5)
    audit_path = tmp_path / "audit.jsonl"
    audit = LocalReviewAudit(audit_path)
    for stage in ("computed", "rejected"):
        assert audit(dict(kind="security-review.v1", stage=stage)) is True
    assert len(audit_path.read_text().splitlines()) == 2
    if os.name != "nt":
        assert audit_path.stat().st_mode & 0o077 == 0
        audit_path.chmod(0o644)
        with pytest.raises(ContractError):
            audit(dict(kind="security-review.v1", stage="computed"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX projected symlink and FIFO behavior")
def test_projected_symlink_supported_but_fifo_and_audit_symlink_rejected(tmp_path):
    source = tmp_path / "current-token"
    source.write_bytes(b"current")
    link = tmp_path / "projected-token"
    link.symlink_to(source)
    assert mounted_bytes(link, limit=16) == b"current"
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ContractError):
        mounted_bytes(fifo, limit=16)  # nonblocking open; never wait for a writer
    with pytest.raises(OSError):
        LocalReviewAudit(link)(dict(kind="security-review.v1", stage="computed"))


def test_server_config_rejects_implicit_defaults_and_unknown_fields(tmp_path):
    from sova_security.interfaces.review_server import app_from_config
    path = tmp_path / "config.json"
    path.write_text('{"schema_version":1}')
    with pytest.raises(ContractError):
        app_from_config(path)
