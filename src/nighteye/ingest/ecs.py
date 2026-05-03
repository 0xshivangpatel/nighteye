"""ECS (Elastic Common Schema) v8.x field mapping helpers.

Maps forensic tool output fields to standardized ECS fields, plus
NightEye extension fields (nighteye.*). This ensures all evidence
in OpenSearch follows a uniform schema regardless of source tool.

References:
    - docs/ARCHITECTURE.md § 13 (OpenSearch index design and ECS mapping)
    - Elastic ECS v8.x: https://www.elastic.co/guide/en/ecs/current/index.html
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "ECS_CORE_FIELDS",
    "NIGHTEYE_FIELDS",
    "build_ecs_doc",
    "case_index_pattern",
    "compute_doc_id",
    "make_index_name",
    "normalize_timestamp",
]


# ============================================================
# ECS core field definitions
# ============================================================

ECS_CORE_FIELDS: dict[str, str] = {
    # Field name → OpenSearch type
    "@timestamp": "date",
    "host.name": "keyword",
    "host.os.family": "keyword",
    "event.code": "keyword",
    "event.action": "keyword",
    "event.category": "keyword",
    "event.outcome": "keyword",
    "user.name": "keyword",
    "user.domain": "keyword",
    "user.id": "keyword",
    "process.pid": "long",
    "process.parent.pid": "long",
    "process.name": "keyword",
    "process.command_line": "text",
    "process.executable": "keyword",
    "process.hash.sha256": "keyword",
    "file.path": "keyword",
    "file.hash.sha256": "keyword",
    "source.ip": "ip",
    "source.port": "long",
    "destination.ip": "ip",
    "destination.port": "long",
    "network.protocol": "keyword",
    "winlog.event_data": "object",
}


# ============================================================
# NightEye extension fields
# ============================================================

NIGHTEYE_FIELDS: dict[str, str] = {
    "nighteye.ingest_id": "keyword",
    "nighteye.source_file": "keyword",
    "nighteye.audit_id": "keyword",
    "nighteye.parser": "keyword",
    "nighteye.parser_version": "keyword",
    "nighteye.canonical_type": "keyword",
    "nighteye.source_doc_ids": "keyword",
    "nighteye.cluster_ids": "keyword",
    "nighteye.verdict": "keyword",
    "nighteye.evidence_disturbed": "boolean",
}


# ============================================================
# Index naming
# ============================================================


def _sanitize_index_component(s: str) -> str:
    """Lowercase + dash-encode a string for safe use in an OpenSearch index name.

    OpenSearch index names are case-insensitive and disallow many characters;
    we always lowercase and replace whitespace/slashes with hyphens. This is
    the canonical sanitizer for any index-name component.
    """
    return s.lower().replace(" ", "-").replace("/", "-").replace("\\", "-")


def make_index_name(case_id: str, artifact_type: str, host: str) -> str:
    """Build an OpenSearch index name following the NightEye convention.

    Format: ``case-{case_id}-{artifact_type}-{host}``

    All components are lowercased and sanitized for OpenSearch.

    Examples:
        >>> make_index_name("INC-2026-001", "evtx", "DC01")
        'case-inc-2026-001-evtx-dc01'
    """
    return (
        f"case-{_sanitize_index_component(case_id)}"
        f"-{_sanitize_index_component(artifact_type)}"
        f"-{_sanitize_index_component(host)}"
    )


def case_index_pattern(case_id: str, suffix: str = "*") -> str:
    """Build a case-scoped index pattern using the same sanitizer as
    :func:`make_index_name`.

    This is the **only** correct way to compose a wildcard for
    ``client.list_indices()`` or scroll search across a case — naive
    ``f"case-{case_id}-*"`` interpolation breaks because OpenSearch
    auto-lowercases index names at creation time, while the case_id
    stored in ``CASE.yaml`` typically has mixed case (``INC-2026-...``).
    The wildcard would then never match the real indices.

    Examples:
        >>> case_index_pattern("INC-2026-001")
        'case-inc-2026-001-*'
        >>> case_index_pattern("INC-2026-001", "canonical-*")
        'case-inc-2026-001-canonical-*'
        >>> case_index_pattern("INC-2026-001", "evtx-DC01")
        'case-inc-2026-001-evtx-dc01'
    """
    base = f"case-{_sanitize_index_component(case_id)}"
    if not suffix or suffix == "*":
        return f"{base}-*"
    # The suffix is allowed to contain wildcards; sanitize the
    # non-wildcard segments. Splitting on '*' preserves the wildcards.
    sanitized = "*".join(
        _sanitize_index_component(seg) if seg else seg
        for seg in suffix.split("*")
    )
    return f"{base}-{sanitized}"


# ============================================================
# Document ID (idempotent)
# ============================================================


def compute_doc_id(case_id: str, artifact_type: str, host: str,
                   canonical_fields: str) -> str:
    """Compute a deterministic document ID for idempotent indexing.

    ``doc_id = sha256(case_id + ":" + artifact_type + ":" + host + ":" +
                      canonical_event_fields)``

    Re-ingesting the same evidence produces the same doc_id, enabling
    ``update_or_create`` semantics.
    """
    payload = f"{case_id}:{artifact_type}:{host}:{canonical_fields}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ============================================================
# Timestamp normalization
# ============================================================


def normalize_timestamp(ts: str | datetime | None) -> str | None:
    """Normalize a timestamp to ISO 8601 UTC string with ms precision.

    Handles various input formats from forensic tools:
    - ISO 8601 strings (with or without timezone)
    - datetime objects
    - Windows FILETIME-style strings
    - None (returns None)

    Returns:
        ISO 8601 UTC string like "2026-04-29T14:23:07.412Z", or None.
    """
    if ts is None:
        return None

    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    if isinstance(ts, str):
        if not ts.strip():
            return None
        try:
            # Handle "Z" suffix
            clean = ts.strip()
            if clean.endswith("Z"):
                clean = clean[:-1] + "+00:00"
            dt = datetime.fromisoformat(clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        except (ValueError, TypeError):
            return None

    return None


# ============================================================
# ECS document builder
# ============================================================


def build_ecs_doc(
    *,
    timestamp: str | datetime | None = None,
    host_name: str = "",
    event_code: str = "",
    event_action: str = "",
    event_category: str | list[str] = "",
    event_outcome: str = "",
    user_name: str = "",
    user_domain: str = "",
    user_id: str = "",
    process_pid: int | None = None,
    process_parent_pid: int | None = None,
    process_name: str = "",
    process_command_line: str = "",
    process_executable: str = "",
    process_hash_sha256: str = "",
    file_path: str = "",
    file_hash_sha256: str = "",
    source_ip: str = "",
    source_port: int | None = None,
    destination_ip: str = "",
    destination_port: int | None = None,
    network_protocol: str = "",
    winlog_event_data: dict[str, Any] | None = None,
    # NightEye extension fields
    nighteye_ingest_id: str = "",
    nighteye_source_file: str = "",
    nighteye_audit_id: str = "",
    nighteye_parser: str = "",
    nighteye_parser_version: str = "",
    nighteye_canonical_type: str = "",
    nighteye_verdict: str = "",
    nighteye_evidence_disturbed: bool = False,
    # Additional fields
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a standardized ECS document for OpenSearch indexing.

    Only non-empty fields are included in the output to keep
    documents compact.

    Returns:
        A dict ready for OpenSearch bulk indexing.
    """
    doc: dict[str, Any] = {}

    # Timestamp
    ts = normalize_timestamp(timestamp)
    if ts:
        doc["@timestamp"] = ts

    # Host
    if host_name:
        doc.setdefault("host", {})["name"] = host_name

    # Event
    event: dict[str, Any] = {}
    if event_code:
        event["code"] = event_code
    if event_action:
        event["action"] = event_action
    if event_category:
        if isinstance(event_category, list):
            event["category"] = event_category
        elif event_category:
            event["category"] = [event_category]
    if event_outcome:
        event["outcome"] = event_outcome
    if event:
        doc["event"] = event

    # User
    user: dict[str, Any] = {}
    if user_name:
        user["name"] = user_name
    if user_domain:
        user["domain"] = user_domain
    if user_id:
        user["id"] = user_id
    if user:
        doc["user"] = user

    # Process
    process: dict[str, Any] = {}
    if process_pid is not None:
        process["pid"] = process_pid
    if process_parent_pid is not None:
        process.setdefault("parent", {})["pid"] = process_parent_pid
    if process_name:
        process["name"] = process_name
    if process_command_line:
        process["command_line"] = process_command_line
    if process_executable:
        process["executable"] = process_executable
    if process_hash_sha256:
        process.setdefault("hash", {})["sha256"] = process_hash_sha256
    if process:
        doc["process"] = process

    # File
    file_obj: dict[str, Any] = {}
    if file_path:
        file_obj["path"] = file_path
    if file_hash_sha256:
        file_obj.setdefault("hash", {})["sha256"] = file_hash_sha256
    if file_obj:
        doc["file"] = file_obj

    # Network source
    source: dict[str, Any] = {}
    if source_ip:
        source["ip"] = source_ip
    if source_port is not None:
        source["port"] = source_port
    if source:
        doc["source"] = source

    # Network destination
    dest: dict[str, Any] = {}
    if destination_ip:
        dest["ip"] = destination_ip
    if destination_port is not None:
        dest["port"] = destination_port
    if dest:
        doc["destination"] = dest

    if network_protocol:
        doc.setdefault("network", {})["protocol"] = network_protocol

    # Winlog
    if winlog_event_data:
        doc.setdefault("winlog", {})["event_data"] = winlog_event_data

    # NightEye extension fields
    ne: dict[str, Any] = {}
    if nighteye_ingest_id:
        ne["ingest_id"] = nighteye_ingest_id
    if nighteye_source_file:
        ne["source_file"] = nighteye_source_file
    if nighteye_audit_id:
        ne["audit_id"] = nighteye_audit_id
    if nighteye_parser:
        ne["parser"] = nighteye_parser
    if nighteye_parser_version:
        ne["parser_version"] = nighteye_parser_version
    if nighteye_canonical_type:
        ne["canonical_type"] = nighteye_canonical_type
    if nighteye_verdict:
        ne["verdict"] = nighteye_verdict
    if nighteye_evidence_disturbed:
        ne["evidence_disturbed"] = True
    if ne:
        doc["nighteye"] = ne

    # Extra fields
    if extra:
        doc.update(extra)

    return doc
