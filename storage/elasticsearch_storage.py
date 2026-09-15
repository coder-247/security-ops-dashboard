import hashlib
import json
import os
from typing import Any

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk


DEFAULT_ELASTICSEARCH_URL = "http://localhost:9200"

INDEX_DEFINITIONS = {
    "security-events": {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "event": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "kind": {"type": "keyword"},
                        "category": {"type": "keyword"},
                        "action": {"type": "keyword"},
                        "outcome": {"type": "keyword"},
                    }
                },
                "log": {
                    "properties": {
                        "source": {"type": "keyword"},
                    }
                },
                "source": {
                    "properties": {
                        "ip": {
                            "type": "ip",
                            "ignore_malformed": True,
                        }
                    }
                },
                "destination": {
                    "properties": {
                        "ip": {
                            "type": "ip",
                            "ignore_malformed": True,
                        }
                    }
                },
                "trace": {
                    "properties": {
                        "id": {"type": "keyword"},
                    }
                },
                "rule": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "risk_score": {"type": "integer"},
                    }
                },
                "tags": {"type": "keyword"},
            }
        }
    },
    "security-alerts": {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "event": {
                    "properties": {
                        "id": {"type": "keyword"},
                    }
                },
                "source": {
                    "properties": {
                        "ip": {
                            "type": "ip",
                            "ignore_malformed": True,
                        }
                    }
                },
                "trace": {
                    "properties": {
                        "id": {"type": "keyword"},
                    }
                },
                "rule": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "name": {"type": "text"},
                        "severity": {"type": "keyword"},
                        "risk_score": {"type": "integer"},
                    }
                },
                "tags": {"type": "keyword"},
            }
        }
    },
    "security-incidents": {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "incident_id": {"type": "keyword"},
                "trace_id": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "risk_score": {"type": "integer"},
                "event_count": {"type": "integer"},
                "source_ips": {
                    "type": "ip",
                    "ignore_malformed": True,
                },
                "rule_ids": {"type": "keyword"},
                "timeline": {
                    "type": "object",
                    "enabled": False,
                },
            }
        }
    },
    "parser-metrics": {
        "mappings": {
            "properties": {
                "generated_at": {"type": "date"},
                "total_files": {"type": "integer"},
                "successful_files": {"type": "integer"},
                "failed_files": {"type": "integer"},
                "total_events": {"type": "integer"},
                "parse_success_rate": {"type": "float"},
                "parse_failure_rate": {"type": "float"},
            }
        }
    },
}


def get_nested_value(
    document: dict[str, Any],
    *keys: str,
) -> Any:
    value: Any = document

    for key in keys:
        if not isinstance(value, dict):
            return None

        value = value.get(key)

    return value


def create_document_id(
    index_name: str,
    document: dict[str, Any],
) -> str:
    event_id = get_nested_value(
        document,
        "event",
        "id",
    )
    rule_id = get_nested_value(
        document,
        "rule",
        "id",
    )

    if index_name == "security-events" and event_id:
        return str(event_id)

    if index_name == "security-alerts":
        if event_id and rule_id:
            return f"{event_id}-{rule_id}"

    if index_name == "security-incidents":
        incident_id = document.get("incident_id")

        if incident_id:
            return str(incident_id)

    canonical_json = json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )

    return hashlib.sha256(
        canonical_json.encode("utf-8")
    ).hexdigest()


class ElasticsearchStorage:
    def __init__(
        self,
        url: str | None = None,
    ) -> None:
        elasticsearch_url = (
            url
            or os.getenv("ELASTICSEARCH_URL")
            or DEFAULT_ELASTICSEARCH_URL
        )

        self.client = Elasticsearch(
            elasticsearch_url,
            request_timeout=10,
        )

    def is_available(self) -> bool:
        try:
            return bool(self.client.ping())
        except Exception:
            return False

    def ensure_indices(self) -> None:
        for index_name, definition in (
            INDEX_DEFINITIONS.items()
        ):
            if self.client.indices.exists(
                index=index_name
            ):
                continue

            self.client.indices.create(
                index=index_name,
                mappings=definition["mappings"],
            )

    def save_documents(
        self,
        index_name: str,
        documents: list[dict[str, Any]],
    ) -> int:
        if not documents:
            return 0

        if index_name not in INDEX_DEFINITIONS:
            raise ValueError(
                f"지원하지 않는 인덱스입니다: {index_name}"
            )

        actions = [
            {
                "_index": index_name,
                "_id": create_document_id(
                    index_name,
                    document,
                ),
                "_source": document,
            }
            for document in documents
        ]

        success_count, _ = bulk(
            self.client,
            actions,
            refresh=True,
        )

        return success_count

    def close(self) -> None:
        self.client.close()


if __name__ == "__main__":
    storage = ElasticsearchStorage()

    if not storage.is_available():
        raise SystemExit(
            "Elasticsearch에 연결할 수 없습니다."
        )

    storage.ensure_indices()
    storage.close()

    print("Elasticsearch 연결 및 인덱스 생성 완료")