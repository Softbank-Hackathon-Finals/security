from datetime import UTC, datetime, timedelta
from pathlib import Path
import json
from sova_security.contracts.commands import ResourceScope
from sova_security.contracts.evidence import RevisionSet
from sova_security.domain.team_controls import (
    TeamControlRegistration,
    TeamControlBinding,
)


def team_control_bundle():
    raw = (
        Path(__file__)
        .parent
        .joinpath("fixtures/team-control-source-run-v1.json")
        .read_bytes()
    )
    body = json.loads(raw)
    now = datetime(2026, 11, 4, 9, 4, 20, tzinfo=UTC)
    scope = ResourceScope("tenant-a", "demo-chat", "env-aws", "registered-app")
    profile = TeamControlRegistration(
        scope,
        RevisionSet(*[c * 64 for c in "abcd"]),
        "aws:eks/source",
        "source",
        tuple(
            TeamControlBinding(
                row["test_id"], "1", row["expected"], row["expected"] == "deny"
            )
            for row in body["results"]
        ),
        86400,
        now - timedelta(minutes=10),
        now + timedelta(hours=1),
    )
    return body, profile, now
