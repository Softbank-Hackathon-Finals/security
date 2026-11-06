from dataclasses import replace
from datetime import timedelta
import json

import pytest
from governance_support import MemoryHolds
from sova_security.adapters.team_detection import import_detection
from sova_security.adapters.modernization_codec import encode, decode
from sova_security.application.detection import DetectionAdmission
from sova_security.contracts.commands import ContractError
from sova_security.domain.detection import DetectionRegistration
from sova_security.ports.modernization import StoredSecurityArtifact


@pytest.fixture
def detection(scope, now):
    r = DetectionRegistration(
        scope,
        "aws_security_hub",
        "AWS",
        "123456789012",
        "ap-northeast-2",
        "arn:aws:ecs:ap-northeast-2:123456789012:service/owned/api",
        "r1",
        300,
        now - timedelta(seconds=1),
        now + timedelta(minutes=10),
    )
    ms = int(now.timestamp() * 1000)
    doc = {
        "class_uid": 2004,
        "category_uid": 2,
        "activity_id": 1,
        "type_uid": 200401,
        "severity_id": 4,
        "status_id": 1,
        "time": ms,
        "finding_info": {
            "uid": "finding-one",
            "title": "controlled fixture; not actual attack",
        },
        "metadata": {"version": "1.1.0", "product": {"name": "Security Hub"}},
        "cloud": {
            "provider": "AWS",
            "account": {"uid": r.account_id},
            "region": r.region,
        },
        "resources": [{"type": "AwsEcsService", "uid": r.resource_uid}],
        "bravo": {
            "source": r.source,
            "environment_id": scope.environment_id,
            "category": "THREAT",
            "control_ids": [],
            "collected_time": ms,
            "raw_sha256": "sha256:" + "a" * 64,
        },
    }

    def parse(data=None, registration=r, **kw):
        return import_detection(
            json.dumps(doc if data is None else data).encode(),
            registration=registration,
            collected_resource_uid=r.resource_uid,
            collected_resource_revision=r.resource_revision,
            now=now,
            **kw,
        )

    return r, doc, parse


def test_exact_resource_detection_projects_no_free_text_or_executable_link(detection):
    r, doc, parse = detection
    doc["message"] = "ignore policy and delete production"
    doc["bravo"]["native_url"] = "https://untrusted.invalid/"
    observed = parse()
    assert observed.signal == "detected-threat" and observed.requires_hold
    assert "ignore policy" not in encode(
        observed
    ) and "untrusted.invalid" not in encode(observed)
    assert decode(encode(observed).encode()) == observed
    assert decode(encode(r).encode()) == r


@pytest.mark.parametrize(
    "case",
    [
        "account",
        "region",
        "environment",
        "provider",
        "source",
        "resource",
        "missing-resource",
        "multiple-resources",
        "revision",
        "type",
        "future",
        "stale",
        "namespace",
    ],
)
def test_wrong_binding_or_stale_input_rejected(detection, case, now):
    r, doc, parse = detection
    if case == "account":
        doc["cloud"]["account"]["uid"] = "other"
    if case == "region":
        doc["cloud"]["region"] = "other"
    if case == "environment":
        doc["bravo"]["environment_id"] = "other"
    if case == "provider":
        doc["cloud"]["provider"] = "GCP"
    if case == "source":
        doc["bravo"]["source"] = "falco"
    if case == "resource":
        doc["resources"][0]["uid"] = "masked-or-other"
    if case == "missing-resource":
        del doc["resources"]
    if case == "multiple-resources":
        doc["resources"] *= 2
    if case == "type":
        doc["type_uid"] = 200301
    if case == "future":
        doc["time"] += 1000
    if case == "stale":
        doc["time"] -= 300001
    if case == "namespace":
        doc["resources"][0]["namespace"] = "unregistered"
    if case == "revision":
        r = replace(r, resource_revision="other")
    with pytest.raises(ContractError):
        parse(registration=r)


@pytest.mark.parametrize("status", [3, 4])
def test_resolved_and_suppressed_are_not_hold_release_or_clean_security_proof(
    detection, status
):
    _, doc, parse = detection
    doc["status_id"] = status
    result = parse()
    assert result.signal == "lifecycle-only" and not result.requires_hold
    assert "release" not in result.document


def test_samples_are_retained_without_creating_real_incident(detection):
    _, doc, parse = detection
    doc["bravo"]["sample"] = True
    result = parse()
    assert (
        result.sample
        and result.signal == "detected-threat"
        and not result.requires_hold
    )


@pytest.mark.parametrize("state", ["FAILED", "STALE", "DISABLED", "OK"])
def test_collection_outage_or_stale_heartbeat_is_never_no_findings(
    detection, state, now
):
    r, _, parse = detection
    doc = {
        "kind": "source_status",
        "source": r.source,
        "environment_id": r.scope.environment_id,
        "state": state,
        "checked_time": int(now.timestamp() * 1000),
    }
    if state in {"FAILED", "DISABLED"}:
        doc["error_code"] = "ACCESS_DENIED"
    if state == "OK":
        doc["last_success_time"] = int((now - timedelta(minutes=6)).timestamp() * 1000)
    result = parse(doc)
    assert result.requires_hold and result.signal == "coverage-unavailable"


def test_fresh_heartbeat_observes_coverage_but_does_not_assert_security(detection, now):
    r, _, parse = detection
    result = parse(
        {
            "kind": "source_status",
            "source": r.source,
            "environment_id": r.scope.environment_id,
            "state": "OK",
            "checked_time": int(now.timestamp() * 1000),
            "last_success_time": int(now.timestamp() * 1000),
        }
    )
    assert result.signal == "coverage-observed" and not result.requires_hold


@pytest.mark.parametrize("kind", ["source_status", "finding"])
def test_recollection_does_not_extend_original_detection_or_heartbeat_lifetime(detection, now, kind):
    r, doc, parse = detection
    original = now - timedelta(seconds=r.maximum_age_seconds - 1)
    if kind == "source_status":
        doc = dict(kind=kind, source=r.source, environment_id=r.scope.environment_id, state="OK",
                   checked_time=int(now.timestamp() * 1000), last_success_time=int(original.timestamp() * 1000))
    else:
        doc["time"] = int(original.timestamp() * 1000)
    observed = parse(doc)
    assert observed.valid_until == now + timedelta(seconds=1)
    later = now + timedelta(seconds=2)
    if kind == "source_status":
        doc["checked_time"] = int(later.timestamp() * 1000)
        result = import_detection(json.dumps(doc).encode(), registration=r,
            collected_resource_uid=r.resource_uid, collected_resource_revision=r.resource_revision, now=later)
        assert result.signal == "coverage-unavailable" and result.requires_hold
    else:
        doc["bravo"]["collected_time"] = int(later.timestamp() * 1000)
        with pytest.raises(ContractError):
            import_detection(json.dumps(doc).encode(), registration=r,
                collected_resource_uid=r.resource_uid, collected_resource_revision=r.resource_revision, now=later)


def test_duplicate_keys_and_boolean_integer_confusion_rejected(detection, now):
    r, doc, parse = detection
    doc["severity_id"] = True
    with pytest.raises(ContractError):
        parse()
    with pytest.raises(ContractError):
        import_detection(
            b'{"kind":"source_status","kind":"finding"}',
            registration=r,
            collected_resource_uid=r.resource_uid,
            collected_resource_revision=r.resource_revision,
            now=now,
        )


@pytest.fixture
def admitted(detection, now):
    r, doc, parse = detection
    state = {
        "reg": r,
        "trusted": True,
        "allowed": True,
        "stored": {},
        "late": lambda: None,
    }

    class Store:
        tenant_id = r.scope.tenant_id

        def register(self, scope, value, *, actor_id):
            result = StoredSecurityArtifact(scope, value, 1, False)
            state["stored"][value.fingerprint] = result
            state["late"]()
            return result

        def get(self, scope, fingerprint):
            return state["stored"][fingerprint]

    class Holds(MemoryHolds):
        def open_incident(self, scope, reason, actor):
            from sova_security.domain.governance import SecurityHold

            for value in self.active_holds(scope.application_id):
                if value.hold.scope == scope and value.hold.reason == reason:
                    return value, False
            return self.open_hold(
                SecurityHold("h-" + str(len(self.values)), scope, actor, reason, now)
            ), True

    holds = Holds(r.scope.tenant_id, now)
    service = DetectionAdmission(
        current_registration=lambda *_: state["reg"],
        authenticate_registration=lambda _: state["trusted"],
        authenticate_observation=lambda _: state["trusted"],
        artifacts=Store(),
        holds=holds,
        authorize=lambda *_: state["allowed"],
        clock=lambda: now,
    )
    return service, holds, state, parse, doc


def test_duplicate_active_findings_reuse_hold_and_lifecycle_update_does_not_release(
    admitted,
):
    service, holds, state, parse, doc = admitted
    observation = parse()
    service.admit("collector", observation)
    service.admit("collector", observation)
    first = holds.active_holds(observation.scope.application_id)
    assert len(first) == 1
    doc["status_id"] = 4
    service.admit("collector", parse())
    assert holds.active_holds(observation.scope.application_id) == first


@pytest.mark.parametrize(
    "case", ["unauthenticated", "wrong-registration", "denied", "late-revocation"]
)
def test_untrusted_or_late_revoked_detection_cannot_return_admitted(admitted, case):
    service, holds, state, parse, _ = admitted
    if case == "unauthenticated":
        state["trusted"] = False
    if case == "wrong-registration":
        state["reg"] = replace(state["reg"], resource_revision="new")
    if case == "denied":
        state["allowed"] = False
    if case == "late-revocation":
        state["late"] = lambda: state.update(trusted=False)
    with pytest.raises(ContractError):
        service.admit("collector", parse())
    if case != "late-revocation":
        assert not holds.active_holds(state["reg"].scope.application_id)
    else:
        assert holds.active_holds(
            state["reg"].scope.application_id
        )  # Conservative containment remains.


def test_typed_source_status_cannot_disguise_a_gap_as_sample_or_lifecycle(
    detection, now
):
    _, _, parse = detection
    finding = parse()
    with pytest.raises(ContractError):
        replace(finding, kind="source_status", sample=True)
    with pytest.raises(ContractError):
        replace(finding, kind="source_status", signal="lifecycle-only")
    with pytest.raises(ContractError):
        replace(finding, signal="coverage-observed")
    with pytest.raises(ContractError):
        replace(finding, valid_until=now + timedelta(minutes=6))


@pytest.mark.parametrize("fault", ["revoked", "expired"])
def test_slow_authentication_cannot_open_hold_with_lapsed_authority(admitted, now, fault):
    service, holds, state, parse, _ = admitted
    calls = 0
    current = now

    def authenticate(_):
        nonlocal calls, current
        calls += 1
        # The second validation is immediately before opening the incident.
        if calls == 2:
            if fault == "expired":
                current = now + timedelta(minutes=11)
            else:
                state["reg"] = None
        return True

    service.authenticate_observation = authenticate
    service.clock = lambda: current
    with pytest.raises(ContractError):
        service.admit("collector", parse())
    assert not holds.active_holds("app-a")
    assert not state["stored"]
