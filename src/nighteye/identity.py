"""Examiner identity resolution.

Resolution order (highest priority first):
  1. --examiner CLI flag (passed as `flag_override`)
  2. NIGHTEYE_EXAMINER environment variable
  3. ~/.nighteye/config.yaml `examiner` field
  4. OS username (sanitized to a valid slug)

A valid examiner slug is lowercase alphanumeric + hyphens, 1-20 chars,
starting with a letter or digit. This matches the canonical_key rules
in the SQL schema.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import yaml

_EXAMINER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")
_NIGHTEYE_DIR = Path.home() / ".nighteye"
_CONFIG_FILE = _NIGHTEYE_DIR / "config.yaml"


class IdentityError(ValueError):
    """Raised when an examiner identity cannot be resolved or is invalid."""


def is_valid_examiner(slug: str) -> bool:
    """Return True if slug matches the canonical examiner format."""
    return bool(_EXAMINER_RE.match(slug))


def sanitize_slug(raw: str) -> str:
    """Coerce a raw string into a valid examiner slug.

    Lowercases, replaces invalid characters with hyphens, trims hyphens,
    truncates to 20 chars. Returns 'unknown' if nothing salvageable.
    """
    slug = re.sub(r"[^a-z0-9-]", "-", raw.lower()).strip("-")[:20]
    slug = slug.lstrip("-")
    return slug or "unknown"


def get_examiner(flag_override: str | None = None) -> str:
    """Resolve examiner identity from all sources, returning a valid slug."""
    if flag_override:
        slug = sanitize_slug(flag_override)
        if not is_valid_examiner(slug):
            raise IdentityError(f"Invalid examiner from --examiner: {flag_override!r}")
        return slug

    env = os.environ.get("NIGHTEYE_EXAMINER", "").strip()
    if env:
        slug = sanitize_slug(env)
        if not is_valid_examiner(slug):
            raise IdentityError(f"Invalid NIGHTEYE_EXAMINER: {env!r}")
        return slug

    if _CONFIG_FILE.exists():
        try:
            with open(_CONFIG_FILE, encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            cfg_examiner = (cfg.get("examiner") or "").strip()
            if cfg_examiner:
                slug = sanitize_slug(cfg_examiner)
                if is_valid_examiner(slug):
                    return slug
        except (OSError, yaml.YAMLError) as err:
            print(
                f"Warning: could not read {_CONFIG_FILE}: {err}",
                file=sys.stderr,
            )

    os_user = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
    return sanitize_slug(os_user)


def warn_if_unconfigured(slug: str) -> None:
    """Print a warning if the slug looks like a fallback to OS user."""
    env = os.environ.get("NIGHTEYE_EXAMINER", "").strip()
    if env:
        return
    if _CONFIG_FILE.exists():
        try:
            with open(_CONFIG_FILE, encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            if (cfg.get("examiner") or "").strip():
                return
        except (OSError, yaml.YAMLError):
            pass
    os_user = os.environ.get("USER") or os.environ.get("USERNAME") or ""
    if slug == sanitize_slug(os_user):
        print(
            f"Note: examiner '{slug}' resolved from OS user. "
            f"Run `nighteye config --examiner <name>` to set explicitly.",
            file=sys.stderr,
        )
