"""The new workflow driver must not bypass the existing SHIFT admission owner."""

import pytest

from platform_review_support import platform_admission as pinned_admission

platform_admission = pinned_admission


@pytest.mark.parametrize("platform_admission", ["initial", "post_apply"], indirect=True)
def test_workflow_driver_does_not_take_shift_execution_ownership(platform_admission):
    fixture = platform_admission
    if fixture.platform_baseline != "bb174860bedf100de3970c3e8e410f02f23994e2":
        pytest.skip("Workflow host did not exist in this historical baseline")
    from bravo_platform_events.workflow import WorkflowRecovery
    from bravo_platform_events.workflow_host import DRIVEN, StageReaders, WorkflowHost

    assert "SHIFT" not in DRIVEN
    with pytest.raises(ValueError, match="unknown_or_invalid_stage_reader"):
        StageReaders({"SHIFT": lambda *_: None})
    driver = WorkflowHost(WorkflowRecovery(fixture.service, read_evidence=StageReaders({})))
    assert fixture.store.snapshot(fixture.plan.plan_id)["state"] == "SHIFT"
    assert driver.active() == [] and driver.sweep() == []
    assert not fixture.requests


@pytest.mark.parametrize("platform_admission", ["initial"], indirect=True)
def test_prepared_stage_reader_is_not_reused_for_a_new_plan_version(platform_admission):
    if platform_admission.platform_baseline != "bb174860bedf100de3970c3e8e410f02f23994e2":
        pytest.skip("Workflow host did not exist in this historical baseline")
    from bravo_platform_events.store import EventError
    from bravo_platform_events.workflow_host import StageReaders

    calls = []
    def prepare(plan_id, tenant_id, version):
        calls.append((plan_id, tenant_id, version))
        return lambda *_: "prepared-for-this-version"
    readers = StageReaders({}, preparers={"ANALYZE": prepare})
    readers.prepare("owned-plan", "owned-tenant", "ANALYZE", 3)
    with pytest.raises(EventError, match="workflow_reader_unwired"):
        readers(None, {"plan_id": "owned-plan", "version": 4, "state": "ANALYZE"}, None, None)
    assert calls == [("owned-plan", "owned-tenant", 3)]
    assert readers(None, {"plan_id": "owned-plan", "version": 3, "state": "ANALYZE"}, None, None) == "prepared-for-this-version"
    with pytest.raises(EventError, match="workflow_reader_unwired"):
        readers(None, {"plan_id": "owned-plan", "version": 3, "state": "ANALYZE"}, None, None)
