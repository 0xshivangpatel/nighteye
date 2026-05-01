"""Canonical Event Normalization Engine.

Converts raw ECS documents from OpenSearch into strictly-typed CanonicalEvents,
then indexes them into canonical host indices for downstream behavior construction.

References:
  - docs/ARCHITECTURE.md § 6 (Layer 2: Canonical Evidence Store)
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Iterator

from nighteye.canonical.types import CanonicalEvent, CanonicalType
from nighteye.ingest.ecs import compute_doc_id, make_index_name, normalize_timestamp

__all__ = ["run_normalization_pass", "normalize_document", "CanonicalNormalizer"]

logger = logging.getLogger("nighteye.canonical.engine")

# ============================================================
# Event ID → Canonical Type Mapping
# ============================================================

# Windows Security Event IDs
_EVENT_ID_TO_CANONICAL: dict[str, CanonicalType] = {
    # Process execution
    "4688": CanonicalType.PROCESS_EXECUTION,
    "1": CanonicalType.PROCESS_EXECUTION,  # Sysmon
    "4689": CanonicalType.PROCESS_EXECUTION,  # Process termination

    # Network
    "5156": CanonicalType.NETWORK_CONNECTION,
    "5157": CanonicalType.NETWORK_CONNECTION,
    "3": CanonicalType.NETWORK_CONNECTION,  # Sysmon
    "22": CanonicalType.NETWORK_CONNECTION,  # Sysmon DNS

    # Authentication
    "4624": CanonicalType.AUTHENTICATION,
    "4625": CanonicalType.AUTHENTICATION,
    "4634": CanonicalType.AUTHENTICATION,
    "4647": CanonicalType.AUTHENTICATION,
    "4648": CanonicalType.AUTHENTICATION,
    "4672": CanonicalType.AUTHENTICATION,

    # File operations
    "4663": CanonicalType.FILE_CREATION,  # Object access (simplified)
    "11": CanonicalType.FILE_CREATION,  # Sysmon file create
    "23": CanonicalType.FILE_DELETION,  # Sysmon file delete

    # Registry
    "12": CanonicalType.REGISTRY_MODIFICATION,  # Sysmon
    "13": CanonicalType.REGISTRY_MODIFICATION,  # Sysmon
    "4657": CanonicalType.REGISTRY_MODIFICATION,

    # Service
    "7045": CanonicalType.SERVICE_INSTALLATION,
    "7036": CanonicalType.SERVICE_INSTALLATION,  # Service state change
    "4697": CanonicalType.SERVICE_INSTALLATION,  # Service install

    # Scheduled Task
    "4698": CanonicalType.SCHEDULED_TASK,
    "4702": CanonicalType.SCHEDULED_TASK,

    # Alerts from detection engines
    "sigma-alert": CanonicalType.ALERT,
    "hayabusa-alert": CanonicalType.ALERT,
    "chainsaw-alert": CanonicalType.ALERT,
}

# Event action → Canonical Type fallback
_ACTION_TO_CANONICAL: dict[str, CanonicalType] = {
    "process-created": CanonicalType.PROCESS_EXECUTION,
    "process-create": CanonicalType.PROCESS_EXECUTION,
    "logon-success": CanonicalType.AUTHENTICATION,
    "logon-failure": CanonicalType.AUTHENTICATION,
    "service-installed": CanonicalType.SERVICE_INSTALLATION,
    "scheduled-task-created": CanonicalType.SCHEDULED_TASK,
    "network-connection-allowed": CanonicalType.NETWORK_CONNECTION,
    "network-connection-blocked": CanonicalType.NETWORK_CONNECTION,
    "object-access-attempt": CanonicalType.FILE_CREATION,
    "object-deleted": CanonicalType.FILE_DELETION,
    "registry-key-modified": CanonicalType.REGISTRY_MODIFICATION,
    "script-block-logged": CanonicalType.PROCESS_EXECUTION,
    "sigma-alert": CanonicalType.ALERT,
}

# ============================================================
# Normalizer
# ============================================================

class CanonicalNormalizer:
    """Converts raw ECS documents to CanonicalEvents."""

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.stats = {
            "raw_docs_scanned": 0,
            "canonical_docs_created": 0,
            "errors": 0,
            "skipped": 0,
        }

    def normalize(self, doc: dict[str, Any]) -> CanonicalEvent | None:
        """Convert a single ECS document to CanonicalEvent."""
        self.stats["raw_docs_scanned"] += 1

        try:
            source = doc.get("_source", doc)
            
            # Check if this is already a CanonicalEvent dictionary (from canonical index)
            if "canonical_type" in source and "host_name" in source and "event_id" in source:
                return CanonicalEvent(
                    event_id=source["event_id"],
                    case_id=self.case_id,
                    host_name=source["host_name"],
                    timestamp=source.get("@timestamp", source.get("timestamp", "")),
                    canonical_type=CanonicalType(source["canonical_type"]),
                    source_index=source.get("source_index", ""),
                    source_doc_id=source.get("source_doc_id", ""),
                    user=source.get("user", ""),
                    process_name=source.get("process_name", ""),
                    process_path=source.get("process_path", ""),
                    pid=source.get("pid"),
                    command_line=source.get("command_line", ""),
                    target_file=source.get("target_file", ""),
                    remote_ip=source.get("remote_ip", ""),
                    remote_port=source.get("remote_port"),
                    registry_key=source.get("registry_key", ""),
                    alert_name=source.get("alert_name", ""),
                    alert_level=source.get("alert_level", ""),
                    raw_data=source.get("raw_data", source),
                )

            canonical_type = self._determine_canonical_type(source)
            if canonical_type is None:
                self.stats["skipped"] += 1
                return None

            host_name = self._extract_host(source)
            timestamp = self._extract_timestamp(source)

            # Build canonical event ID
            canonical_fields = f"{host_name}:{canonical_type.value}:{timestamp}:{self._extract_key_fields(source, canonical_type)}"
            event_id = hashlib.sha256(
                f"{self.case_id}:{canonical_fields}".encode()
            ).hexdigest()[:32]

            event = CanonicalEvent(
                event_id=event_id,
                case_id=self.case_id,
                host_name=host_name,
                timestamp=timestamp or "",
                canonical_type=canonical_type,
                source_index=doc.get("_index", ""),
                source_doc_id=doc.get("_id", ""),
                user=self._extract_user(source),
                process_name=self._extract_process_name(source),
                process_path=self._extract_process_path(source),
                pid=self._extract_pid(source),
                command_line=self._extract_command_line(source),
                target_file=self._extract_file_path(source),
                remote_ip=self._extract_remote_ip(source),
                remote_port=self._extract_remote_port(source),
                registry_key=self._extract_registry_key(source),
                alert_name=self._extract_alert_name(source),
                alert_level=self._extract_alert_level(source),
                raw_data=source,
            )

            self.stats["canonical_docs_created"] += 1
            return event

        except Exception as exc:
            self.stats["errors"] += 1
            logger.debug("Normalization failed for doc: %s", exc)
            return None

    def _determine_canonical_type(self, doc: dict[str, Any]) -> CanonicalType | None:
        """Determine the canonical type from ECS document fields."""
        # Priority 1: nighteye.canonical_type if already set
        ne_type = doc.get("nighteye", {}).get("canonical_type", "")
        if ne_type:
            try:
                return CanonicalType(ne_type)
            except ValueError:
                pass

        # Priority 2: event.code (Event ID)
        event_code = str(doc.get("event", {}).get("code", ""))
        if event_code in _EVENT_ID_TO_CANONICAL:
            return _EVENT_ID_TO_CANONICAL[event_code]

        # Priority 3: event.action
        action = doc.get("event", {}).get("action", "").lower()
        if action in _ACTION_TO_CANONICAL:
            return _ACTION_TO_CANONICAL[action]

        # Priority 4: event.category
        category = doc.get("event", {}).get("category", "")
        if isinstance(category, list):
            category = category[0] if category else ""
        category_map = {
            "authentication": CanonicalType.AUTHENTICATION,
            "process": CanonicalType.PROCESS_EXECUTION,
            "network": CanonicalType.NETWORK_CONNECTION,
            "file": CanonicalType.FILE_CREATION,
            "registry": CanonicalType.REGISTRY_MODIFICATION,
            "configuration": CanonicalType.SERVICE_INSTALLATION,
            "intrusion_detection": CanonicalType.ALERT,
        }
        if category in category_map:
            return category_map[category]

        # Priority 5: Volatility plugin type
        vol_plugin = doc.get("volatility", {}).get("plugin", "")
        if vol_plugin:
            if "pslist" in vol_plugin or "pstree" in vol_plugin:
                return CanonicalType.PROCESS_EXECUTION
            if "netscan" in vol_plugin:
                return CanonicalType.NETWORK_CONNECTION
            if "malfind" in vol_plugin:
                return CanonicalType.ALERT

        # Priority 6: Hayabusa/Chainsaw alert
        if doc.get("event", {}).get("kind") == "alert":
            return CanonicalType.ALERT

        return None

    def _extract_host(self, doc: dict[str, Any]) -> str:
        """Extract host name from ECS document."""
        host = doc.get("host", {}).get("name", "")
        if not host:
            # Fallback: computer from winlog
            host = doc.get("winlog", {}).get("computer", "")
        if not host:
            # Fallback: from source_file path
            source = doc.get("nighteye", {}).get("source_file", "")
            if source:
                parts = source.replace("\\", "/").split("/")
                # Heuristic: look for host-like directory
                for part in parts:
                    if any(p in part.lower() for p in ["dc", "srv", "wkstn", "pc", "host"]):
                        return part
        return host or "unknown-host"

    def _extract_timestamp(self, doc: dict[str, Any]) -> str:
        """Extract and normalize timestamp."""
        ts = doc.get("@timestamp", "")
        if ts:
            norm = normalize_timestamp(ts)
            return norm or ts
        return ""

    def _extract_user(self, doc: dict[str, Any]) -> str:
        """Extract user name from ECS document."""
        user = doc.get("user", {}).get("name", "")
        domain = doc.get("user", {}).get("domain", "")
        if domain and user:
            return f"{domain}\\{user}"
        return user or ""

    def _extract_process_name(self, doc: dict[str, Any]) -> str:
        """Extract process name."""
        return doc.get("process", {}).get("name", "")

    def _extract_process_path(self, doc: dict[str, Any]) -> str:
        """Extract process executable path."""
        return doc.get("process", {}).get("executable", "")

    def _extract_pid(self, doc: dict[str, Any]) -> int | None:
        """Extract process PID."""
        pid = doc.get("process", {}).get("pid")
        if pid is not None:
            try:
                return int(pid)
            except (ValueError, TypeError):
                pass
        return None

    def _extract_command_line(self, doc: dict[str, Any]) -> str:
        """Extract command line."""
        return doc.get("process", {}).get("command_line", "")

    def _extract_file_path(self, doc: dict[str, Any]) -> str:
        """Extract file path."""
        return doc.get("file", {}).get("path", "")

    def _extract_remote_ip(self, doc: dict[str, Any]) -> str:
        """Extract remote IP."""
        # Prefer destination for outbound
        dst = doc.get("destination", {}).get("ip", "")
        if dst:
            return dst
        # Fallback to source if no destination
        return doc.get("source", {}).get("ip", "")

    def _extract_remote_port(self, doc: dict[str, Any]) -> int | None:
        """Extract remote port."""
        port = doc.get("destination", {}).get("port")
        if port is None:
            port = doc.get("source", {}).get("port")
        if port is not None:
            try:
                return int(port)
            except (ValueError, TypeError):
                pass
        return None

    def _extract_registry_key(self, doc: dict[str, Any]) -> str:
        """Extract registry key path."""
        return doc.get("registry", {}).get("key", "")

    def _extract_alert_name(self, doc: dict[str, Any]) -> str:
        """Extract alert name from detection engine output."""
        # Hayabusa/Chainsaw
        rule = doc.get("rule", {}).get("name", "")
        if rule:
            return rule
        # Generic alert
        return doc.get("alert", {}).get("name", "")

    def _extract_alert_level(self, doc: dict[str, Any]) -> str:
        """Extract alert severity level."""
        return doc.get("rule", {}).get("level", "") or doc.get("alert", {}).get("level", "")

    def _extract_key_fields(self, doc: dict[str, Any], canonical_type: CanonicalType) -> str:
        """Extract fields that make this event unique for ID generation."""
        if canonical_type == CanonicalType.PROCESS_EXECUTION:
            return f"{doc.get('process', {}).get('name', '')}:{doc.get('process', {}).get('pid', '')}"
        elif canonical_type == CanonicalType.AUTHENTICATION:
            return f"{doc.get('user', {}).get('name', '')}:{doc.get('source', {}).get('ip', '')}"
        elif canonical_type == CanonicalType.NETWORK_CONNECTION:
            return f"{doc.get('source', {}).get('ip', '')}:{doc.get('destination', {}).get('ip', '')}:{doc.get('destination', {}).get('port', '')}"
        elif canonical_type == CanonicalType.FILE_CREATION:
            return doc.get("file", {}).get("path", "")
        elif canonical_type == CanonicalType.REGISTRY_MODIFICATION:
            return doc.get("registry", {}).get("key", "")
        elif canonical_type == CanonicalType.SERVICE_INSTALLATION:
            return doc.get("service", {}).get("name", "")
        elif canonical_type == CanonicalType.SCHEDULED_TASK:
            return doc.get("task", {}).get("name", "")
        elif canonical_type == CanonicalType.ALERT:
            return doc.get("rule", {}).get("name", "")
        return ""


# ============================================================
# Pass Runner
# ============================================================

def run_normalization_pass(client, case_id: str) -> dict[str, Any]:
    """Run the canonical normalization pass over all raw indices for a case.

    Args:
        client: NightEyeOSClient instance
        case_id: Case ID to normalize

    Returns:
        Statistics dict with counts
    """
    normalizer = CanonicalNormalizer(case_id)

    # Find all raw indices for this case (exclude canonical and clusters)
    all_indices = client.list_indices(f"case-{case_id}-*")
    raw_indices = [
        idx for idx in all_indices
        if "-canonical-" not in idx and "-clusters" not in idx
    ]

    logger.info("Normalizing %d raw indices for case %s", len(raw_indices), case_id)

    canonical_docs_by_host: dict[str, list[dict]] = {}

    for index_name in raw_indices:
        logger.debug("Normalizing index: %s", index_name)

        try:
            # Scroll through all docs in index
            for page in client.scroll_search_iter(
                index=index_name,
                query={"match_all": {}},
                page_size=1000,
            ):
                for doc in page:
                    canonical_event = normalizer.normalize(doc)
                    if canonical_event:
                        host = canonical_event.host_name
                        if host not in canonical_docs_by_host:
                            canonical_docs_by_host[host] = []
                        canonical_docs_by_host[host].append(canonical_event.to_dict())

        except Exception as exc:
            logger.warning("Failed to normalize index %s: %s", index_name, exc)
            normalizer.stats["errors"] += 1

    # Index canonical documents
    for host, docs in canonical_docs_by_host.items():
        canonical_index = make_index_name(case_id, "canonical", host)

        # Generate deterministic doc IDs
        doc_ids = [
            compute_doc_id(
                case_id, "canonical", host,
                f"{d.get('canonical_type')}:{d.get('@timestamp')}:{d.get('event_id')}"
            )
            for d in docs
        ]

        try:
            client.bulk_index(canonical_index, docs, doc_ids=doc_ids)
            logger.info("Indexed %d canonical events to %s", len(docs), canonical_index)
        except Exception as exc:
            logger.error("Failed to index canonical docs to %s: %s", canonical_index, exc)
            normalizer.stats["errors"] += len(docs)

    logger.info(
        "Normalization complete: %d scanned, %d created, %d errors, %d skipped",
        normalizer.stats["raw_docs_scanned"],
        normalizer.stats["canonical_docs_created"],
        normalizer.stats["errors"],
        normalizer.stats["skipped"],
    )

    return normalizer.stats


def normalize_document(doc: dict[str, Any], case_id: str) -> CanonicalEvent | None:
    """Normalize a single document (convenience function)."""
    normalizer = CanonicalNormalizer(case_id)
    return normalizer.normalize(doc)
