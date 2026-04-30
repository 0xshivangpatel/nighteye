"""OpenSearch client wrapper with bulk indexing and circuit breaker.

Provides:
- Connection management with retry and health checks
- Bulk indexer with configurable batch size
- Shard breaker (circuit breaker after N consecutive bulk failures)
- Index template installation
- Document count and search helpers

All OpenSearch operations go through this module. The agent and
constructors never call opensearch-py directly.

References:
    - docs/ARCHITECTURE.md § 13 (OpenSearch index design)
    - docs/ARCHITECTURE.md § 16 (Failure handling: shard breaker)
    - docs/BUILD_PLAN.md D4 (opensearch_client.py)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from opensearchpy import OpenSearch, helpers

from nighteye.ingest.index_template import TEMPLATE_NAME, build_index_template

__all__ = [
    "OSConfig",
    "NightEyeOSClient",
]

logger = logging.getLogger("nighteye.opensearch")


# ============================================================
# Configuration
# ============================================================


@dataclass
class OSConfig:
    """OpenSearch connection configuration."""
    url: str = "http://127.0.0.1:9200"
    username: str | None = None
    password: str | None = None
    verify_certs: bool = False
    bulk_batch_size: int = 5000
    shard_breaker_threshold: int = 3
    timeout: int = 30


# ============================================================
# Client
# ============================================================


class NightEyeOSClient:
    """Wrapper around opensearch-py with NightEye-specific operations.

    Usage::

        client = NightEyeOSClient(OSConfig())
        client.connect()
        client.ensure_template()
        client.bulk_index("case-inc-001-evtx-dc01", docs)
        client.close()
    """

    def __init__(self, config: OSConfig | None = None) -> None:
        self._config = config or OSConfig()
        self._client: OpenSearch | None = None
        self._consecutive_failures: int = 0
        self._breaker_tripped: bool = False

    @property
    def connected(self) -> bool:
        return self._client is not None

    @property
    def breaker_tripped(self) -> bool:
        return self._breaker_tripped

    def connect(self) -> dict[str, Any]:
        """Connect to OpenSearch and return cluster info.

        Raises:
            ConnectionError: If OpenSearch is unreachable.
        """
        auth = None
        if self._config.username and self._config.password:
            auth = (self._config.username, self._config.password)

        self._client = OpenSearch(
            hosts=[self._config.url],
            http_auth=auth,
            verify_certs=self._config.verify_certs,
            timeout=self._config.timeout,
        )

        try:
            info = self._client.info()
            logger.info(
                "Connected to OpenSearch %s at %s",
                info.get("version", {}).get("number", "unknown"),
                self._config.url,
            )
            return info
        except Exception as exc:
            self._client = None
            raise ConnectionError(
                f"OpenSearch at {self._config.url} not responding: {exc}"
            ) from exc

    def close(self) -> None:
        """Close the OpenSearch connection."""
        if self._client:
            self._client.close()
            self._client = None

    def health(self) -> dict[str, Any]:
        """Return cluster health status."""
        self._require_connection()
        return self._client.cluster.health()  # type: ignore[union-attr]

    def ensure_template(self) -> bool:
        """Install the NightEye index template if not already present.

        Returns:
            True if template was created, False if it already existed.
        """
        self._require_connection()
        assert self._client is not None

        # Check if template exists
        try:
            existing = self._client.indices.get_index_template(name=TEMPLATE_NAME)
            if existing:
                logger.info("Index template '%s' already exists", TEMPLATE_NAME)
                return False
        except Exception:
            pass  # Template doesn't exist, create it

        template = build_index_template()
        self._client.indices.put_index_template(
            name=TEMPLATE_NAME,
            body=template,
        )
        logger.info("Installed index template '%s'", TEMPLATE_NAME)
        return True

    def bulk_index(
        self,
        index: str,
        docs: list[dict[str, Any]],
        doc_ids: list[str] | None = None,
    ) -> dict[str, int]:
        """Bulk index documents into OpenSearch.

        Splits into batches of ``bulk_batch_size`` and indexes each batch.
        If ``shard_breaker_threshold`` consecutive batches fail, the
        circuit breaker trips and all further indexing is refused.

        Args:
            index: Target index name.
            docs: List of document bodies.
            doc_ids: Optional list of document IDs (same length as docs).
                     If provided, enables idempotent update-or-create.

        Returns:
            Dict with keys: indexed, errors, total.

        Raises:
            RuntimeError: If the circuit breaker has tripped.
            ConnectionError: If not connected.
        """
        self._require_connection()
        assert self._client is not None

        if self._breaker_tripped:
            raise RuntimeError(
                f"Shard breaker tripped after {self._config.shard_breaker_threshold} "
                f"consecutive failures. Resolve OpenSearch issues and reconnect."
            )

        batch_size = self._config.bulk_batch_size
        total_indexed = 0
        total_errors = 0

        for i in range(0, len(docs), batch_size):
            batch = docs[i:i + batch_size]
            batch_ids = doc_ids[i:i + batch_size] if doc_ids else None

            actions = []
            for j, doc in enumerate(batch):
                action: dict[str, Any] = {
                    "_index": index,
                    "_source": doc,
                }
                if batch_ids and j < len(batch_ids):
                    action["_id"] = batch_ids[j]
                actions.append(action)

            try:
                success, errors = helpers.bulk(
                    self._client,
                    actions,
                    raise_on_error=False,
                    raise_on_exception=False,
                )
                error_count = len(errors) if isinstance(errors, list) else 0
                total_indexed += success
                total_errors += error_count

                if error_count > 0:
                    self._consecutive_failures += 1
                    logger.warning(
                        "Bulk batch %d-%d: %d indexed, %d errors",
                        i, i + len(batch), success, error_count,
                    )
                else:
                    self._consecutive_failures = 0

                if self._consecutive_failures >= self._config.shard_breaker_threshold:
                    self._breaker_tripped = True
                    logger.error(
                        "Shard breaker tripped after %d consecutive failures!",
                        self._consecutive_failures,
                    )
                    raise RuntimeError(
                        f"Shard breaker tripped: {self._consecutive_failures} "
                        f"consecutive bulk failures"
                    )

            except RuntimeError:
                raise  # re-raise breaker trips
            except Exception as exc:
                self._consecutive_failures += 1
                total_errors += len(batch)
                logger.error("Bulk batch failed: %s", exc)

                if self._consecutive_failures >= self._config.shard_breaker_threshold:
                    self._breaker_tripped = True
                    raise RuntimeError(
                        f"Shard breaker tripped: {self._consecutive_failures} "
                        f"consecutive bulk failures"
                    ) from exc

        return {
            "indexed": total_indexed,
            "errors": total_errors,
            "total": len(docs),
        }

    def doc_count(self, index: str) -> int:
        """Return the document count for an index (or wildcard pattern).

        Returns 0 if the index doesn't exist.
        """
        self._require_connection()
        assert self._client is not None
        try:
            result = self._client.count(index=index)
            return result.get("count", 0)
        except Exception:
            return 0

    def search(
        self,
        index: str,
        query: dict[str, Any],
        size: int = 100,
    ) -> list[dict[str, Any]]:
        """Execute a search query and return hits.

        Args:
            index: Index name or wildcard pattern.
            query: OpenSearch query DSL body.
            size: Maximum number of hits to return.

        Returns:
            List of hit ``_source`` dicts.
        """
        self._require_connection()
        assert self._client is not None
        result = self._client.search(
            index=index,
            body={"query": query, "size": size},
        )
        return [hit["_source"] for hit in result["hits"]["hits"]]

    def delete_index(self, index: str) -> bool:
        """Delete an index. Returns True if deleted, False if not found."""
        self._require_connection()
        assert self._client is not None
        try:
            self._client.indices.delete(index=index)
            return True
        except Exception:
            return False

    def reset_breaker(self) -> None:
        """Reset the circuit breaker after resolving issues."""
        self._breaker_tripped = False
        self._consecutive_failures = 0
        logger.info("Shard breaker reset")

    def _require_connection(self) -> None:
        if self._client is None:
            raise ConnectionError(
                "Not connected to OpenSearch. Call connect() first."
            )
