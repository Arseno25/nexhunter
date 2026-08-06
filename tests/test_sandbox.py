"""File ops + python execution helpers."""

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.execution.sandbox import (
    list_dir,
    python_run,
    read_file,
    write_file,
)


def test_write_and_read_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr("nexhunter.execution.sandbox.DEFAULT_ALLOW_ROOT", tmp_path)
    ok = write_file("notes.txt", "hello lab")
    assert ok["ok"] is True
    assert (tmp_path / "notes.txt").read_text() == "hello lab"
    got = read_file(str(tmp_path / "notes.txt"))
    assert got["content"] == "hello lab"
    assert got["bytes"] == 9


def test_write_escapes_denied():
    bad = write_file("../../etc/cron.d/owned", "x")
    assert bad["ok"] is False
    assert "allow root" in bad["error"]


def test_read_missing_file():
    assert read_file("/nonexistent/file_xyz")["ok"] is False


def test_list_dir_shows_entries(tmp_path, monkeypatch):
    monkeypatch.setattr("nexhunter.execution.sandbox.DEFAULT_ALLOW_ROOT", tmp_path)
    write_file("a.txt", "a")
    write_file("b.txt", "b")
    (tmp_path / "sub").mkdir()
    res = list_dir("")
    assert res["ok"] is True
    names = {e["name"] for e in res["entries"]}
    assert {"a.txt", "b.txt", "sub"} <= names


def test_python_run_ok_and_error():
    good = python_run("print(sum(range(100)))")
    assert good["ok"] is True
    assert "4950" in good["stdout"]

    bad = python_run("raise ValueError('boom')")
    assert bad["ok"] is False
    assert "boom" in bad["stderr"]


def test_python_run_requires_code():
    assert python_run("  ")["ok"] is False
