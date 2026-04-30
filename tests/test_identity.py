"""Tests for examiner identity resolution."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from nighteye.identity import (
    IdentityError,
    get_examiner,
    is_valid_examiner,
    sanitize_slug,
)


def test_is_valid_examiner_accepts_canonical_slug() -> None:
    assert is_valid_examiner("alice")
    assert is_valid_examiner("alice-doe")
    assert is_valid_examiner("a1b2c3")
    assert is_valid_examiner("0xshivangpatel")


def test_is_valid_examiner_rejects_bad_slugs() -> None:
    assert not is_valid_examiner("")
    assert not is_valid_examiner("Alice")          # uppercase
    assert not is_valid_examiner("-alice")         # leading hyphen
    assert not is_valid_examiner("alice_doe")      # underscore not allowed
    assert not is_valid_examiner("alice.doe")
    assert not is_valid_examiner("a" * 21)         # too long


def test_sanitize_slug_replaces_invalid_chars() -> None:
    assert sanitize_slug("Alice Doe") == "alice-doe"
    assert sanitize_slug("Alice_Doe") == "alice-doe"
    assert sanitize_slug("alice.doe") == "alice-doe"
    assert sanitize_slug("ALICE!") == "alice"


def test_sanitize_slug_truncates_to_20() -> None:
    assert len(sanitize_slug("a" * 100)) == 20


def test_sanitize_slug_returns_unknown_when_empty_after_clean() -> None:
    assert sanitize_slug("!@#$") == "unknown"
    assert sanitize_slug("---") == "unknown"


def test_get_examiner_flag_override_wins(nighteye_home: Path) -> None:
    assert get_examiner("alice") == "alice"


def test_get_examiner_flag_override_sanitizes_valid(nighteye_home: Path) -> None:
    """Inputs that sanitize to valid slugs should succeed, not raise."""
    # "ALICE_DOE!" sanitizes to "alice-doe" which is valid
    assert get_examiner("ALICE_DOE!") == "alice-doe"


def test_get_examiner_env_var(
    nighteye_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NIGHTEYE_EXAMINER", "bob")
    assert get_examiner() == "bob"


def test_get_examiner_config_file(nighteye_home: Path) -> None:
    nighteye_home.mkdir(parents=True, exist_ok=True)
    cfg = nighteye_home / "config.yaml"
    cfg.write_text(yaml.safe_dump({"examiner": "carol"}), encoding="utf-8")
    assert get_examiner() == "carol"


def test_get_examiner_falls_back_to_os_user(
    nighteye_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("USER", "TestUser-09")
    monkeypatch.setenv("USERNAME", "TestUser-09")  # Windows
    assert get_examiner() == "testuser-09"


def test_priority_flag_beats_env_beats_config(
    nighteye_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nighteye_home.mkdir(parents=True, exist_ok=True)
    (nighteye_home / "config.yaml").write_text(
        yaml.safe_dump({"examiner": "from-config"}), encoding="utf-8"
    )
    monkeypatch.setenv("NIGHTEYE_EXAMINER", "from-env")
    assert get_examiner("from-flag") == "from-flag"
    assert get_examiner() == "from-env"
    monkeypatch.delenv("NIGHTEYE_EXAMINER")
    assert get_examiner() == "from-config"
