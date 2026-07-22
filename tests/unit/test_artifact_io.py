from __future__ import annotations

from pathlib import Path

import pytest

from pqtrust_agent.metrics.artifact_io import staged_report_dir


def test_staged_report_dir_refuses_nonempty_without_replace(tmp_path: Path) -> None:
    output = tmp_path / "report"
    output.mkdir()
    (output / "old.txt").write_text("old", encoding="utf-8")

    with pytest.raises(FileExistsError), staged_report_dir(output, replace_existing=False):
        pass

    assert (output / "old.txt").read_text(encoding="utf-8") == "old"


def test_staged_report_dir_replaces_atomically(tmp_path: Path) -> None:
    output = tmp_path / "report"
    output.mkdir()
    (output / "old.txt").write_text("old", encoding="utf-8")

    with staged_report_dir(output, replace_existing=True) as staging:
        (staging / "new.txt").write_text("new", encoding="utf-8")

    assert not (output / "old.txt").exists()
    assert (output / "new.txt").read_text(encoding="utf-8") == "new"
