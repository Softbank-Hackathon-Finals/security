"""Read a pinned platform source; run one synthetic operator, never real tools."""

import argparse
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types

BASELINE = "98885a69999398bfe3f49fbc8324a7b19aae3e16"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", type=Path, required=True)
    args = parser.parse_args()
    root = args.platform.resolve()
    git = ["git", "-c", f"safe.directory={root.as_posix()}", "-C", str(root)]
    assert subprocess.check_output(git + ["rev-parse", "HEAD"], text=True).strip() == BASELINE
    assert not subprocess.check_output(git + ["status", "--porcelain"])
    source = subprocess.check_output(git + ["show", BASELINE + ":scripts/happy_path.py"])
    module = types.ModuleType("qualified_t28_restart_probe")
    module.__file__ = str(root / "scripts/happy_path.py")
    sys.modules[module.__name__] = module
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    # Replace the complete operator sequence before invoking cmd_run. No real
    # tool or process is reachable through this synthetic run callback.
    module.STEPS = (module.Step("synthetic-effect", "test", "operator", "test",
                               "owned in-memory effect", command=("never-executed",)),)
    effects = []

    class InterruptedAfterEffect(BaseException):
        pass

    def synthetic_run(argv, **_):
        assert argv == ["never-executed"]
        effects.append("in-memory-only")
        if len(effects) == 1:
            raise InterruptedAfterEffect()
        return types.SimpleNamespace(returncode=0, stdout='{"result":"synthetic-done"}')

    with tempfile.TemporaryDirectory(prefix="sova-t28-restart-probe-") as directory:
        record = Path(directory) / "run.jsonl"
        record.write_text(json.dumps({"kind": "header", "plan_id": "owned-plan"}) + "\n")
        options = types.SimpleNamespace(record=str(record), plan_id="owned-plan", plan_state_command=None,
            kubeconfig=None, fault_record="unused", application_id=None, receipts=None, step_timeout=1)
        with redirect_stdout(io.StringIO()):
            try:
                module.cmd_run(options, run=synthetic_run)
            except InterruptedAfterEffect:
                pass
            else:
                raise AssertionError("Synthetic interruption did not escape")
            incomplete_lines = len(record.read_text().splitlines())
            before_retry = len(effects)
            code = module.cmd_run(options, run=synthetic_run)
        assert before_retry == 1 and incomplete_lines == 1 and code == module.DONE and len(effects) == 2
    print(json.dumps(dict(platform_sha=BASELINE, path="scripts/happy_path.py",
        source_sha256=hashlib.sha256(source).hexdigest(), scenario="interrupted-after-effect-before-record",
        effect_kind="synthetic in-memory callback", real_operator_commands=0,
        effects_before_restart=before_retry, effects_after_restart=len(effects),
        persisted_lines_after_interruption=incomplete_lines, resumed_exit_code=code,
        qualification="BLOCK", execution_authorized=False), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
