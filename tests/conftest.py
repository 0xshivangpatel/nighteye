"""Shared pytest fixtures for NightEye tests.

Every test that touches case state or the global ~/.nighteye directory
must use the `nighteye_home` fixture so it doesn't pollute the developer's
real home directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def nighteye_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect ~/.nighteye to a tmp path for test isolation.

    Patches module-level constants in `nighteye.case` and
    `nighteye.identity` since they're computed at import time from
    `Path.home()`.
    """
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    fake_nighteye = fake_home / ".nighteye"

    import nighteye.case as case_mod
    import nighteye.identity as identity_mod

    monkeypatch.setattr(case_mod, "_NIGHTEYE_DIR", fake_nighteye)
    monkeypatch.setattr(case_mod, "_ACTIVE_CASE_FILE", fake_nighteye / "active_case")
    monkeypatch.setattr(identity_mod, "_NIGHTEYE_DIR", fake_nighteye)
    monkeypatch.setattr(identity_mod, "_CONFIG_FILE", fake_nighteye / "config.yaml")

    # Drop env vars that would override identity/case lookups
    monkeypatch.delenv("NIGHTEYE_EXAMINER", raising=False)
    monkeypatch.delenv("NIGHTEYE_CASE_DIR", raising=False)

    return fake_nighteye


@pytest.fixture
def cases_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Provide a tmp cases directory and set NIGHTEYE_CASES_DIR."""
    cd = tmp_path / "cases"
    cd.mkdir()
    monkeypatch.setenv("NIGHTEYE_CASES_DIR", str(cd))
    return cd
