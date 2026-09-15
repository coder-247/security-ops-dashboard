from unittest.mock import MagicMock

import pytest

import storage.elasticsearch_storage as es_module
from storage.elasticsearch_storage import (
    ElasticsearchStorage,
    create_document_id,
    get_nested_value,
)


@pytest.fixture
def storage_and_client(monkeypatch):
    mock_client = MagicMock()

    mock_elasticsearch = MagicMock(
        return_value=mock_client
    )

    monkeypatch.setattr(
        es_module,
        "Elasticsearch",
        mock_elasticsearch,
    )

    storage = ElasticsearchStorage(
        "http://localhost:9200"
    )

    return storage, mock_client


def test_get_nested_value():
    document = {
        "event": {
            "id": "event-001",
        }
    }

    result = get_nested_value(
        document,
        "event",
        "id",
    )

    assert result == "event-001"


def test_get_nested_value_returns_none():
    document = {
        "event": {
            "id": "event-001",
        }
    }

    result = get_nested_value(
        document,
        "source",
        "ip",
    )

    assert result is None


def test_event_document_id():
    document = {
        "event": {
            "id": "event-001",
        }
    }

    document_id = create_document_id(
        "security-events",
        document,
    )

    assert document_id == "event-001"


def test_alert_document_id():
    document = {
        "event": {
            "id": "event-001",
        },
        "rule": {
            "id": "WAF-SQLI-001",
        },
    }

    document_id = create_document_id(
        "security-alerts",
        document,
    )

    assert document_id == (
        "event-001-WAF-SQLI-001"
    )


def test_fallback_document_id_is_stable():
    first_document = {
        "message": "same document",
        "count": 1,
    }

    second_document = {
        "count": 1,
        "message": "same document",
    }

    first_id = create_document_id(
        "parser-metrics",
        first_document,
    )

    second_id = create_document_id(
        "parser-metrics",
        second_document,
    )

    assert first_id == second_id


def test_is_available_returns_true(
    storage_and_client,
):
    storage, mock_client = storage_and_client
    mock_client.ping.return_value = True

    assert storage.is_available() is True


def test_is_available_returns_false_on_error(
    storage_and_client,
):
    storage, mock_client = storage_and_client

    mock_client.ping.side_effect = (
        ConnectionError("connection failed")
    )

    assert storage.is_available() is False


def test_ensure_indices_creates_only_missing_indices(
    storage_and_client,
):
    storage, mock_client = storage_and_client

    mock_client.indices.exists.side_effect = [
        True,
        False,
        False,
        False,
    ]

    storage.ensure_indices()

    assert mock_client.indices.exists.call_count == 4
    assert mock_client.indices.create.call_count == 3


def test_save_documents_returns_zero_for_empty_list(
    storage_and_client,
    monkeypatch,
):
    storage, _ = storage_and_client
    mock_bulk = MagicMock()

    monkeypatch.setattr(
        es_module,
        "bulk",
        mock_bulk,
    )

    result = storage.save_documents(
        "security-events",
        [],
    )

    assert result == 0
    mock_bulk.assert_not_called()


def test_save_documents_rejects_unknown_index(
    storage_and_client,
):
    storage, _ = storage_and_client

    with pytest.raises(
        ValueError,
        match="지원하지 않는 인덱스",
    ):
        storage.save_documents(
            "unknown-index",
            [{"message": "test"}],
        )


def test_save_documents_uses_bulk(
    storage_and_client,
    monkeypatch,
):
    storage, mock_client = storage_and_client

    mock_bulk = MagicMock(
        return_value=(1, [])
    )

    monkeypatch.setattr(
        es_module,
        "bulk",
        mock_bulk,
    )

    documents = [
        {
            "@timestamp": "2026-09-16T02:00:00Z",
            "event": {
                "id": "event-001",
            },
            "log": {
                "source": "nginx",
            },
        }
    ]

    result = storage.save_documents(
        "security-events",
        documents,
    )

    assert result == 1
    mock_bulk.assert_called_once()

    actions = mock_bulk.call_args.args[1]

    assert actions[0]["_index"] == (
        "security-events"
    )
    assert actions[0]["_id"] == "event-001"
    assert actions[0]["_source"] == documents[0]
    assert mock_bulk.call_args.kwargs["refresh"] is True


def test_close_closes_client(
    storage_and_client,
):
    storage, mock_client = storage_and_client

    storage.close()

    mock_client.close.assert_called_once()