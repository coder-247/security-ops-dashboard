import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any


PARSER_NAME = "flask_parser"
PARSER_VERSION = "1.0.0"


def validate_timestamp(
    timestamp_text: str
) -> str:
    """
    ISO 8601 시간 형식이 올바른지 검사합니다.
    """
    if not timestamp_text:
        raise ValueError(
            "Flask 로그에 timestamp가 없습니다."
        )

    normalized_timestamp = (
        timestamp_text.replace(
            "Z",
            "+00:00"
        )
    )

    try:
        datetime.fromisoformat(
            normalized_timestamp
        )

    except ValueError as error:
        raise ValueError(
            "올바르지 않은 Flask 로그 시간입니다: "
            f"{timestamp_text}"
        ) from error

    return timestamp_text


def create_event_id(log_line: str) -> str:
    """
    로그 출처마다 이벤트 ID가 겹치지 않도록
    전체 로그 내용으로 고유한 해시를 만듭니다.
    """
    return hashlib.sha256(
        log_line.encode("utf-8")
    ).hexdigest()


def normalize_outcome(
    original_outcome: str
) -> str:
    """
    애플리케이션마다 다른 결과 표현을
    success 또는 failure로 통일합니다.
    """
    success_values = {
        "success",
        "allowed",
        "approved",
        "completed"
    }

    failure_values = {
        "failure",
        "failed",
        "denied",
        "rejected",
        "error"
    }

    normalized_value = (
        original_outcome.lower()
    )

    if normalized_value in success_values:
        return "success"

    if normalized_value in failure_values:
        return "failure"

    return "unknown"


def create_tags(
    record: dict[str, Any],
    normalized_outcome: str
) -> list[str]:
    tags = [
        "flask",
        "application",
        "application_log"
    ]

    event_type = str(
        record.get("event_type", "")
    ).lower()

    action = str(
        record.get("action", "")
    ).lower()

    if event_type:
        tags.append(event_type)

    if action == "admin_access":
        tags.append("admin_page")

    if normalized_outcome == "failure":
        tags.append("access_denied")

    level = str(
        record.get("level", "")
    ).lower()

    if level:
        tags.append(level)

    return list(
        dict.fromkeys(tags)
    )


def parse_record(
    record: dict[str, Any],
    original_log: str
) -> dict[str, Any]:
    """
    Flask JSON 로그 한 건을 공통 형식으로 변환합니다.
    """
    required_fields = [
        "timestamp",
        "event_type",
        "action",
        "outcome"
    ]

    missing_fields = [
        field
        for field in required_fields
        if field not in record
    ]

    if missing_fields:
        raise ValueError(
            "Flask 로그 필수 필드가 없습니다: "
            + ", ".join(missing_fields)
        )

    original_outcome = str(
        record["outcome"]
    )

    normalized_outcome = normalize_outcome(
        original_outcome
    )

    request_id = record.get(
        "request_id"
    )

    return {
        "@timestamp": validate_timestamp(
            str(record["timestamp"])
        ),
        "schema_version": "1.0.0",
        "event": {
            "id": create_event_id(
                original_log
            ),
            "kind": "event",
            "category": str(
                record["event_type"]
            ),
            "action": str(
                record["action"]
            ),
            "outcome": normalized_outcome,
            "severity": 0,
            "severity_label": "informational",
            "risk_score": 0
        },
        "log": {
            "source": "flask_application",
            "original": original_log
        },
        "source": {
            "ip": record.get("source_ip"),
            "port": None,
            "cidr": None
        },
        "destination": {
            "ip": None,
            "port": 5000,
            "service": record.get(
                "service",
                "flask"
            )
        },
        "network": {
            "transport": "tcp"
        },
        "host": {
            "name": None
        },
        "process": {
            "name": "flask",
            "pid": None
        },
        "application": {
            "service": record.get("service"),
            "environment": record.get(
                "environment"
            ),
            "level": record.get("level"),
            "message": record.get("message"),
            "original_outcome": (
                original_outcome
            )
        },
        "user": {
            "name": record.get("user_id")
        },
        "http": {
            "method": record.get(
                "http_method"
            ),
            "status_code": record.get(
                "status_code"
            ),
            "target_status_code": None,
            "user_agent": None,
            "version": None,
            "request_bytes": None,
            "response_bytes": None,
            "response_time_ms": None
        },
        "url": {
            "full": record.get("path"),
            "path": record.get("path"),
            "query": None
        },
        "cloud": {
            "provider": "aws",
            "service": "ec2",
            "region": "ap-northeast-2",
            "resource_id": None
        },
        "trace": {
            "id": request_id
        },
        "rule": {
            "id": None,
            "name": None,
            "description": None,
            "recommendation": None
        },
        "parser": {
            "name": PARSER_NAME,
            "version": PARSER_VERSION,
            "status": "success"
        },
        "tags": create_tags(
            record,
            normalized_outcome
        )
    }


def parse_line(log_line: str) -> dict[str, Any]:
    """
    JSONL 한 줄을 읽고 Flask 이벤트로 변환합니다.
    """
    clean_line = log_line.strip()

    if not clean_line:
        raise ValueError(
            "Flask 로그가 비어 있습니다."
        )

    try:
        record = json.loads(clean_line)

    except json.JSONDecodeError as error:
        raise ValueError(
            "Flask 로그가 올바른 JSON이 아닙니다."
        ) from error

    if not isinstance(record, dict):
        raise ValueError(
            "Flask 로그는 JSON 객체여야 합니다."
        )

    return parse_record(
        record,
        clean_line
    )


def parse_file(
    file_path: str | Path
) -> list[dict[str, Any]]:
    """
    JSONL 파일을 한 줄씩 파싱합니다.
    """
    path = Path(file_path)
    events = []

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:
        for line_number, line in enumerate(
            file,
            start=1
        ):
            if not line.strip():
                continue

            try:
                event = parse_line(line)
                events.append(event)

            except ValueError as error:
                raise ValueError(
                    f"Flask 로그 "
                    f"{line_number}번째 줄 오류: "
                    f"{error}"
                ) from error

    return events