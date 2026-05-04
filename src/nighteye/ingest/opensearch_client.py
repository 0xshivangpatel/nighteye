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
        # Auto-connect so callers don't need explicit connect()
        try:
            self.connect()
        except ConnectionError:
            logger.warning(
                "OpenSearch not available at %s — ingest will fail. "
                "Start OpenSearch with: docker compose up -d",
                self._config.url,
            )

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

    def index_exists(self, index: str) -> bool:
        """Check if an index exists and has documents."""
        self._require_connection()
        assert self._client is not None
        try:
            count = self._client.count(index=index)
            return count.get("count", 0) > 0
        except Exception:
            return False
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
        Individual doc errors (mapping conflicts, etc.) are logged but do NOT
        abort the batch — other docs in the same batch still get indexed.
        The circuit breaker only trips on connection-level failures where
        OpenSearch itself is unreachable.

        Args:
            index: Target index name.
            docs: List of document bodies.
            doc_ids: Optional list of document IDs (same length as docs).
                     If provided, enables idempotent update-or-create.

        Returns:
            Dict with keys: indexed, errors, total.

        Raises:
            ConnectionError: If not connected.
        """
        self._require_connection()
        assert self._client is not None

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
                    # Log individual doc errors for debugging
                    for err in (errors if isinstance(errors, list) else []):
                        err_type = err.get("index", {}).get("error", {}).get("type", "unknown") if isinstance(err, dict) else ""
                        logger.debug("Doc error in %s: %s", index, err_type)
                    logger.warning(
                        "Bulk batch %d-%d: %d indexed, %d errors — continuing",
                        i, i + len(batch), success, error_count,
                    )

            except Exception as exc:
                # Connection-level failure — log and continue to next batch
                # rather than aborting all remaining docs.
                total_errors += len(batch)
                logger.error("Bulk batch %d-%d failed: %s — skipping, continuing", i, i + len(batch), exc)

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

    def search_raw(
        self,
        index: str,
        query: dict[str, Any],
        from_: int = 0,
        size: int = 100,
    ) -> dict[str, Any]:
        """Execute a search query and return the raw OpenSearch response.

        Args:
            index: Index name or wildcard pattern.
            query: OpenSearch query DSL body.
            from_: Offset for pagination.
            size: Maximum number of hits to return.

        Returns:
            Full OpenSearch search response dict.
        """
        self._require_connection()
        assert self._client is not None
        return self._client.search(
            index=index,
            body={"query": query, "from": from_, "size": size},
        )

    # --------------------------------------------------------
    # Scale features for 50+ host deployments
    # --------------------------------------------------------

    def scroll_search(
        self,
        index: str,
        query: dict[str, Any],
        scroll_timeout: str = "2m",
        page_size: int = 1000,
    ) -> list[dict[str, Any]]:
        """Paginated search using scroll API for large result sets.

        Use this instead of ``search()`` when you expect more than 10K
        results. Automatically paginates through all matching documents.

        For SRL-2018 scale (13 hosts × ~50K events each = ~650K docs),
        scroll avoids deep pagination performance cliffs.

        Args:
            index: Index name or wildcard pattern (e.g. ``case-inc-*``).
            query: OpenSearch query DSL body.
            scroll_timeout: How long to keep the scroll context alive
                between pages. Default "2m".
            page_size: Number of documents per page. Default 1000.

        Returns:
            All matching ``_source`` dicts (may be very large — use
            ``scroll_search_iter`` for memory-efficient streaming).
        """
        all_hits: list[dict[str, Any]] = []
        for page in self.scroll_search_iter(index, query, scroll_timeout, page_size):
            all_hits.extend(page)
        return all_hits

    def scroll_search_iter(
        self,
        index: str,
        query: dict[str, Any],
        scroll_timeout: str = "2m",
        page_size: int = 1000,
    ):
        """Iterator version of scroll_search — yields pages of hits.

        Memory-efficient: only one page of ``page_size`` docs is in
        memory at a time.

        Yields:
            Lists of ``_source`` dicts, one list per scroll page.
        """
        self._require_connection()
        assert self._client is not None

        result = self._client.search(
            index=index,
            body={"query": query, "size": page_size},
            scroll=scroll_timeout,
        )

        scroll_id = result.get("_scroll_id")
        hits = result["hits"]["hits"]

        while hits:
            page = []
            for h in hits:
                src = h["_source"]
                src["_index"] = h["_index"]
                src["_id"] = h["_id"]
                page.append(src)
            yield page

            if not scroll_id:
                break

            result = self._client.scroll(
                scroll_id=scroll_id,
                scroll=scroll_timeout,
            )
            scroll_id = result.get("_scroll_id")
            hits = result["hits"]["hits"]

        # Clean up scroll context
        if scroll_id:
            try:
                self._client.clear_scroll(scroll_id=scroll_id)
            except Exception:
                pass  # best effort cleanup

    def set_refresh_interval(
        self,
        index: str,
        interval: str = "1s",
    ) -> None:
        """Set the refresh interval for an index or wildcard pattern.

        During ingest, set to "30s" or "-1" (disabled) for throughput.
        After ingest, set back to "1s" for search responsiveness.

        For 50+ host ingests, disabling refresh during bulk indexing
        can improve throughput by 2-3x.

        Args:
            index: Index name or wildcard pattern (e.g. ``case-inc-*``).
            interval: Refresh interval. "1s", "30s", or "-1" (disabled).
        """
        self._require_connection()
        assert self._client is not None
        try:
            self._client.indices.put_settings(
                index=index,
                body={"index": {"refresh_interval": interval}},
            )
            logger.info("Set refresh_interval=%s for %s", interval, index)
        except Exception as e:
            # Ignore 404s (index doesn't exist yet) and 429s (rate limited)
            err_str = str(e)
            if "404" in err_str or "index_not_found_exception" in err_str:
                logger.debug("Index %s not found, skipping refresh_interval setting", index)
            elif "429" in err_str:
                import time as _time
                _time.sleep(2)
                logger.debug("Rate limited on refresh_interval for %s, retrying once", index)
                try:
                    self._client.indices.put_settings(
                        index=index,
                        body={"index": {"refresh_interval": interval}},
                    )
                except Exception:
                    pass
            else:
                raise e

    def force_merge(self, index: str, max_segments: int = 1) -> None:
        """Force merge index segments after ingest completes.

        Reduces segment count for faster queries. Only call after
        all ingest for an index is complete (expensive operation).

        Args:
            index: Index name or wildcard pattern.
            max_segments: Target number of segments per shard.
        """
        self._require_connection()
        assert self._client is not None
        self._client.indices.forcemerge(
            index=index,
            max_num_segments=max_segments,
        )
        logger.info("Force merged %s to %d segments", index, max_segments)

    def list_case_indices(self, case_id: str) -> list[dict[str, Any]]:
        """List all indices for a case with doc counts and sizes.

        For a 50-host case with 10 artifact types each, this returns
        ~500 index entries. Useful for ingest progress tracking.

        Args:
            case_id: Case ID (will be lowercased and sanitized).

        Returns:
            List of dicts with keys: index, docs_count, size_bytes.
        """
        self._require_connection()
        assert self._client is not None

        pattern = f"case-{case_id.lower().replace(' ', '-')}*"
        try:
            cat_result = self._client.cat.indices(
                index=pattern,
                format="json",
                h="index,docs.count,store.size",
            )
            results = []
            for entry in cat_result:
                results.append({
                    "index": entry.get("index", ""),
                    "docs_count": int(entry.get("docs.count", 0)),
                    "size": entry.get("store.size", "0b"),
                })
            return sorted(results, key=lambda r: r["index"])
        except Exception:
            return []

    def list_indices(self, pattern: str = "*") -> list[str]:
        self._require_connection()
        assert self._client is not None
        try:
            res = self._client.indices.get(index=pattern)
            return sorted(list(res.keys()))
        except Exception as exc:
            # Log at warning level so we don't silently swallow connection issues
            logger.warning("list_indices failed for pattern %s: %s", pattern, str(exc)[:120])
            return []

    def ingest_stats(self, case_id: str) -> dict[str, Any]:
        """Get aggregate ingest statistics for a case.

        Returns:
            Dict with: total_indices, total_docs, hosts (list of
            host names with per-host doc counts).
        """
        indices = self.list_case_indices(case_id)
        total_docs = sum(i["docs_count"] for i in indices)

        # Extract host names from index names
        # Pattern: case-{case_id}-{artifact_type}-{host}
        hosts: dict[str, int] = {}
        for idx_info in indices:
            parts = idx_info["index"].split("-")
            if len(parts) >= 4:
                host = parts[-1]
                hosts[host] = hosts.get(host, 0) + idx_info["docs_count"]

        return {
            "total_indices": len(indices),
            "total_docs": total_docs,
            "hosts": hosts,
            "indices": indices,
        }

    def bulk_index_iter(
        self,
        index_name: str,
        documents,
        doc_id_fn=None,
        dynamic_routing: bool = False,
    ) -> tuple[int, int]:
        """Streaming bulk index — accepts an iterator of documents.

        Args:
            index_name: Target index name (default if dynamic routing is not used).
            documents: Iterable of document dicts (or tuples of (index, doc) if dynamic_routing=True).
            doc_id_fn: Optional callable(doc) -> str that returns a
                       deterministic document ID for idempotency.
            dynamic_routing: If True, documents iterator must yield (target_index, doc) tuples.

        Returns:
            Tuple of (total_indexed, total_errors).
        """
        self._require_connection()
        assert self._client is not None

        batch: list[dict[str, Any]] = []
        batch_ids: list[str] | None = [] if doc_id_fn else None
        
        total_indexed = 0
        total_errors = 0

        for item in documents:
            if dynamic_routing:
                target_index, doc = item
                action = {"_index": target_index, "_source": doc}
                if doc_id_fn and batch_ids is not None:
                    action["_id"] = doc_id_fn(doc)
                batch.append(action)
            else:
                batch.append(item)
                if doc_id_fn and batch_ids is not None:
                    batch_ids.append(doc_id_fn(item))

            if len(batch) >= self._config.bulk_batch_size:
                if dynamic_routing:
                    # In dynamic routing, the batch is already pre-formatted actions
                    try:
                        success, errors = helpers.bulk(
                            self._client, batch, raise_on_error=False, raise_on_exception=False
                        )
                        total_indexed += success
                        total_errors += len(errors) if isinstance(errors, list) else 0
                    except Exception as exc:
                        logger.error("Dynamic bulk batch failed: %s", exc)
                        total_errors += len(batch)
                else:
                    result = self.bulk_index(index_name, batch, batch_ids)
                    total_indexed += result["indexed"]
                    total_errors += result["errors"]
                
                batch = []
                if batch_ids is not None:
                    batch_ids = []

        # Flush remaining
        if batch:
            if dynamic_routing:
                try:
                    success, errors = helpers.bulk(
                        self._client, batch, raise_on_error=False, raise_on_exception=False
                    )
                    total_indexed += success
                    total_errors += len(errors) if isinstance(errors, list) else 0
                except Exception as exc:
                    logger.error("Dynamic bulk batch failed: %s", exc)
                    total_errors += len(batch)
            else:
                result = self.bulk_index(index_name, batch, batch_ids)
                total_indexed += result["indexed"]
                total_errors += result["errors"]

        return total_indexed, total_errors

    # --------------------------------------------------------
    # Lifecycle
    # --------------------------------------------------------

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
        """Reset the circuit breaker. Call between groups to allow recovery."""
        self._consecutive_failures = 0
        self._breaker_tripped = False
        logger.debug("Circuit breaker reset")
        self._consecutive_failures = 0
        logger.info("Shard breaker reset")

    def _require_connection(self) -> None:
        if self._client is None:
            raise ConnectionError(
                "Not connected to OpenSearch. Call connect() first."
            )
