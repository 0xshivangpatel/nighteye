"""OpenSearch index template installer.

Installs the ``case-*`` index template on first connection. The template
applies to all NightEye evidence indices and sets ECS field mappings,
single shard, zero replicas (single-node deployment).

References:
    - docs/ARCHITECTURE.md § 13 (Index template)
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "TEMPLATE_NAME",
    "build_index_template",
]


TEMPLATE_NAME = "nighteye-case"


def build_index_template() -> dict[str, Any]:
    """Build the OpenSearch index template body for case-* indices.

    Settings:
    - 1 primary shard, 0 replicas (single-node)
    - refresh_interval: 30s during ingest (can be lowered after)
    - Dynamic mapping enabled for unknown fields

    Mappings follow ECS v8.x with NightEye extension fields.

    Returns:
        Dict suitable for ``client.indices.put_index_template()``.
    """
    return {
        "index_patterns": ["case-*"],
        "priority": 100,
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "refresh_interval": "30s",
                "analysis": {
                    "normalizer": {
                        "lowercase_normalizer": {
                            "type": "custom",
                            "filter": ["lowercase"],
                        }
                    }
                },
            },
            "mappings": {
                "dynamic": True,
                "properties": {
                    # Core ECS fields
                    "@timestamp": {"type": "date"},
                    "host": {
                        "properties": {
                            "name": {"type": "keyword"},
                            "os": {
                                "properties": {
                                    "family": {"type": "keyword"},
                                }
                            },
                        }
                    },
                    "event": {
                        "properties": {
                            "code": {"type": "keyword"},
                            "action": {"type": "keyword"},
                            "category": {"type": "keyword"},
                            "outcome": {"type": "keyword"},
                        }
                    },
                    "user": {
                        "properties": {
                            "name": {"type": "keyword"},
                            "domain": {"type": "keyword"},
                            "id": {"type": "keyword"},
                        }
                    },
                    "process": {
                        "properties": {
                            "pid": {"type": "long"},
                            "parent": {
                                "properties": {
                                    "pid": {"type": "long"},
                                }
                            },
                            "name": {"type": "keyword"},
                            "command_line": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 512,
                                    }
                                },
                            },
                            "executable": {"type": "keyword"},
                            "hash": {
                                "properties": {
                                    "sha256": {"type": "keyword"},
                                }
                            },
                        }
                    },
                    "file": {
                        "properties": {
                            "path": {"type": "keyword"},
                            "hash": {
                                "properties": {
                                    "sha256": {"type": "keyword"},
                                }
                            },
                        }
                    },
                    "source": {
                        "properties": {
                            "ip": {"type": "ip"},
                            "port": {"type": "long"},
                        }
                    },
                    "destination": {
                        "properties": {
                            "ip": {"type": "ip"},
                            "port": {"type": "long"},
                        }
                    },
                    "network": {
                        "properties": {
                            "protocol": {"type": "keyword"},
                        }
                    },
                    "winlog": {
                        "properties": {
                            "event_data": {
                                "type": "object",
                                "dynamic": True,
                            },
                        }
                    },
                    # NightEye extension fields
                    "nighteye": {
                        "properties": {
                            "ingest_id": {"type": "keyword"},
                            "source_file": {"type": "keyword"},
                            "audit_id": {"type": "keyword"},
                            "parser": {"type": "keyword"},
                            "parser_version": {"type": "keyword"},
                            "canonical_type": {"type": "keyword"},
                            "source_doc_ids": {"type": "keyword"},
                            "cluster_ids": {"type": "keyword"},
                            "verdict": {"type": "keyword"},
                            "evidence_disturbed": {"type": "boolean"},
                        }
                    },
                },
            },
        },
    }
