"""Protected operator mounts for the standalone service; no enrollment API."""

import base64
from datetime import UTC, datetime
import hashlib
import os
from pathlib import Path
import stat
import threading

from sova_security.adapters.review_https import BearerCredential
from sova_security.adapters.review_identity import WorkloadGrant
from sova_security.adapters.vulnerability_reports import bounded_report
from sova_security.contracts.commands import ContractError, ResourceScope, canonical_json, utc
from sova_security.domain.review_service import ReviewPrincipal


def mounted_bytes(path, *, limit):
    path = Path(path)
    if not path.is_absolute():
        raise ContractError("Absolute protected mount path required")
    # Kubernetes projected credentials use atomic symlinks. The parent mount must
    # be operator-owned/read-only; rejecting every symlink would break rotation.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ContractError("Regular mounted file required")
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ContractError("Mounted file exceeds configured limit")
    return value


class MountedWorkloadGrants:
    def __init__(self, path):
        self.path = path

    def __call__(self, username, uid):
        raw = mounted_bytes(self.path, limit=65536)
        data = bounded_report(raw)
        if set(data) != {"schema_version", "grants"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
            raise ContractError("Unknown workload grant schema")
        if type(data["grants"]) is not list or len(data["grants"]) > 64:
            raise ContractError("Bounded workload grants required")
        seen, selected = set(), None
        for value in data["grants"]:
            if type(value) is not dict or set(value) != {"username", "uid", "subject_id", "tenant_id", "scopes", "modes", "issued_at", "valid_until"}:
                raise ContractError("Explicit workload grant fields required")
            if type(value["scopes"]) is not list or type(value["modes"]) is not list:
                raise ContractError("Typed workload scope and mode lists required")
            scopes = tuple(ResourceScope(**scope) for scope in value["scopes"])
            principal = ReviewPrincipal(value["subject_id"], value["tenant_id"], scopes, tuple(value["modes"]),
                datetime.fromisoformat(value["issued_at"]), datetime.fromisoformat(value["valid_until"]),
                hashlib.sha256(canonical_json(value, limit=65536).encode()).hexdigest())
            grant = WorkloadGrant(value["username"], value["uid"], principal)
            identity = (grant.username, grant.uid)
            if identity in seen:
                raise ContractError("Ambiguous workload identity grant")
            seen.add(identity)
            if identity == (username, uid):
                selected = grant
        return selected


class MountedTokenCredential:
    """Read a projected token each call; the receiving API authenticates it."""

    def __init__(self, path, *, clock):
        self.path, self.clock = path, clock

    def __call__(self):
        token = mounted_bytes(self.path, limit=16384).decode("ascii").strip()
        parts = token.split(".")
        if len(parts) != 3:
            raise ContractError("Expiring projected JWT credential required")
        claims = bounded_report(base64.b64decode(parts[1] + "=" * (-len(parts[1]) % 4), altchars=b"-_", validate=True))
        if type(claims.get("exp")) is not int:
            raise ContractError("Explicit projected credential expiry required")
        value = BearerCredential(token, datetime.fromtimestamp(claims["exp"], UTC))
        if utc(self.clock()) >= value.valid_until:
            raise ContractError("Projected credential expired")
        return value


class LocalReviewAudit:
    """Local durable diagnostic log. NOT T24 immutable audit evidence.

    A protected persistent directory and one service process per file are required.
    Production hosts should provide the existing T24-backed audit callback.
    """

    def __init__(self, path, *, maximum_bytes=16 * 1024 * 1024):
        self.path = Path(path)
        if not self.path.is_absolute():
            raise ContractError("Absolute protected audit path required")
        if type(maximum_bytes) is not int or not 8192 <= maximum_bytes <= 64 * 1024 * 1024:
            raise ContractError("Bounded local audit capacity required")
        self.maximum_bytes = maximum_bytes
        self.lock = threading.Lock()

    def __call__(self, event):
        if type(event) is not dict or event.get("kind") != "security-review.v1" or event.get("stage") not in {"computed", "rejected"}:
            raise ContractError("Fixed review audit event required")
        raw = canonical_json(event, limit=8192).encode() + b"\n"
        flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        with self.lock:
            fd = os.open(self.path, flags, 0o600)
            try:
                info = os.fstat(fd)
                mode = info.st_mode
                if not stat.S_ISREG(mode) or (os.name != "nt" and mode & 0o077):
                    raise ContractError("Private regular audit file required")
                if info.st_size + len(raw) > self.maximum_bytes:
                    raise ContractError("Local audit capacity exhausted")
                if info.st_size:
                    # A crash/full disk can persist only a prefix of a record.
                    # Never merge a new successful event into that torn line.
                    os.lseek(fd, -1, os.SEEK_END)
                    if os.read(fd, 1) != b"\n":
                        raise ContractError("Local audit contains an incomplete record")
                offset = 0
                while offset < len(raw):
                    written = os.write(fd, raw[offset:])
                    if written <= 0:
                        raise OSError("Audit write incomplete")
                    offset += written
                os.fsync(fd)
            finally:
                os.close(fd)
        return True
