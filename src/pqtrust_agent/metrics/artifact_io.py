"""Atomic report-directory helpers."""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def refuse_nonempty_report_dir(path: Path) -> None:
    if path.exists() and any(path.iterdir()):
        raise FileExistsError(
            f"refusing to overwrite non-empty output directory without --replace-existing: {path}"
        )


@contextmanager
def staged_report_dir(output_dir: Path, *, replace_existing: bool) -> Iterator[Path]:
    output_dir = output_dir.resolve()
    parent = output_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    tmp = parent / f".{output_dir.name}.tmp-{os.getpid()}"
    backup = parent / f".{output_dir.name}.old-{os.getpid()}"
    if tmp.exists():
        shutil.rmtree(tmp)
    if backup.exists():
        shutil.rmtree(backup)
    if not replace_existing:
        refuse_nonempty_report_dir(output_dir)
        tmp.mkdir(parents=True)
        try:
            yield tmp
            if output_dir.exists():
                output_dir.rmdir()
            os.replace(tmp, output_dir)
        except Exception:
            if tmp.exists():
                shutil.rmtree(tmp)
            raise
        return

    tmp.mkdir(parents=True)
    try:
        yield tmp
        if output_dir.exists():
            os.replace(output_dir, backup)
        os.replace(tmp, output_dir)
        if backup.exists():
            shutil.rmtree(backup)
    except Exception:
        if tmp.exists():
            shutil.rmtree(tmp)
        if backup.exists() and not output_dir.exists():
            os.replace(backup, output_dir)
        raise
