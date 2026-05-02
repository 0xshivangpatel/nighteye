"""Pure-Python registry hive parser (fallback when RECmd is not available).

Uses ``python-registry`` (Registry) to parse Windows registry hives
on Linux / macOS without requiring Eric Zimmerman's RECmd.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger("nighteye.ingest.python_registry")


def parse_registry_hive(
    hive_path: Path,
    *,
    host_name: str = "",
    source_file: str = "",
    audit_id: str = "",
) -> Iterator[dict[str, Any]]:
    """Yield ECS metadata documents for registry keys in a hive file.

    Args:
        hive_path: Path to the registry hive file (SAM, SYSTEM, etc.)
        host_name: Host name for the host.name ECS field.
        source_file: Source file path for provenance.
        audit_id: Audit trail ID.

    Yields:
        ECS document dicts, one per key found.
    """
    try:
        from Registry import Registry
    except ImportError:
        logger.debug("python-registry not installed; skipping %s", hive_path.name)
        return

    from nighteye.ingest.ecs import build_ecs_doc

    count = 0
    try:
        reg = Registry.Registry(str(hive_path))
        root = reg.root()
        if root is None:
            return

        stack = [(root, root.name())]
        while stack:
            key, key_path = stack.pop()
            try:
                for value in key.values():
                    try:
                        count += 1
                        if count > 100_000:
                            logger.warning(
                                "Registry hive %s exceeded 100k values; truncating",
                                hive_path.name,
                            )
                            return
                        doc = build_ecs_doc(
                            host_name=host_name,
                            event_code="registry_value",
                            event_action="registry-key-parsed",
                            event_category="configuration",
                            nighteye_source_file=str(hive_path),
                            nighteye_audit_id=audit_id,
                            nighteye_parser="python-registry",
                            nighteye_canonical_type="REGISTRY_MODIFICATION",
                            extra={
                                "registry.key": key_path,
                                "registry.value_name": value.name(),
                                "registry.value_type": value.value_type_str(),
                                "nighteye.hive": hive_path.name,
                            },
                        )
                        yield doc
                    except Exception:
                        continue

                for subkey in key.subkeys():
                    stack.append((subkey, f"{key_path}\\{subkey.name()}"))
            except Exception:
                continue
    except Exception as exc:
        logger.warning("Failed to parse registry hive %s: %s", hive_path.name, exc)

    logger.debug("Parsed %s keys from %s", count, hive_path.name)
