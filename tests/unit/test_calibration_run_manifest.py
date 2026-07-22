from __future__ import annotations

import os
from pathlib import Path

import pytest

from pqtrust_agent.crypto.calibration_runner import affinity_command, select_cpu
from pqtrust_agent.crypto.smoke_validation import refuse_nonempty_output_dir
from pqtrust_agent.metrics.run_manifest import scaling_state, thermal_temperatures


def test_run_directory_overwrite_refusal(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "existing").write_text("x", encoding="utf-8")

    with pytest.raises(FileExistsError):
        refuse_nonempty_output_dir(run_dir)


def test_cpu_selection_and_affinity_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "sched_getaffinity", lambda _pid: {2, 3}, raising=False)

    assert select_cpu("auto", None) == 2
    assert select_cpu("3", None) == 3
    assert affinity_command(["native", "--flag"], 3)[-2:] == ["native", "--flag"]


def test_missing_optional_frequency_and_thermal_files_are_null(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = scaling_state(999999)

    assert state["governor"] is None
    assert state["scaling_cur_freq"] is None
    assert isinstance(thermal_temperatures(), dict)
