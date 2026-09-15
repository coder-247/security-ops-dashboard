from pathlib import Path

import pytest

from parsers.flask_parser import (
    normalize_outcome,
    parse_file,
    parse_line
)


PROJECT_ROOT = Path(__file__).parent.parent

SAMPLE_FILE = (
    PROJECT_ROOT
    / "samples"
    / "flask_application.jsonl"
)


def test_flask_file_contains_one_event():
    """
    Flask 샘플 파일에서 이벤트 1건을
    읽는지 확인합니다.
    """
    events = parse_file(SAMPLE_FILE)

    assert len(events) == 1


def test_flask_timestamp():
    """
    Flask 로그의 ISO 시간이 그대로
    보존되는지 확인합니다.
    """
    events = parse_file(SAMPLE_FILE)
    event = events[0]

    assert event["@timestamp"] == (
        "2026-09-16T02:00:00.050Z"
    )


def test_flask_common_event_fields():
    """
    필수 공통 이벤트 필드가 정상적으로
    만들어지는지 확인합니다.
    """
    events = parse_file(SAMPLE_FILE)
    event = events[0]

    assert event["schema_version"] == "1.0.0"

    assert event["event"]["kind"] == "event"

    assert event["event"]["category"] == (
        "authorization"
    )

    assert event["event"]["action"] == (
        "admin_access"
    )

    assert event["log"]["source"] == (
        "flask_application"
    )


def test_denied_outcome_becomes_failure():
    """
    Flask의 denied 결과가 공통값 failure로
    변환되는지 확인합니다.
    """
    events = parse_file(SAMPLE_FILE)
    event = events[0]

    assert event["application"][
        "original_outcome"
    ] == "denied"

    assert event["event"]["outcome"] == (
        "failure"
    )


def test_outcome_normalization():
    """
    애플리케이션마다 다른 결과 표현이
    공통 결과로 변환되는지 확인합니다.
    """
    assert normalize_outcome(
        "success"
    ) == "success"

    assert normalize_outcome(
        "allowed"
    ) == "success"

    assert normalize_outcome(
        "failed"
    ) == "failure"

    assert normalize_outcome(
        "rejected"
    ) == "failure"

    assert normalize_outcome(
        "something_else"
    ) == "unknown"


def test_flask_user_source_and_trace():
    """
    사용자, 출발지 IP, 요청 추적 ID를
    확인합니다.
    """
    events = parse_file(SAMPLE_FILE)
    event = events[0]

    assert event["user"]["name"] == (
        "test-user"
    )

    assert event["source"]["ip"] == (
        "203.0.113.50"
    )

    assert event["trace"]["id"] == (
        "Root=1-68c8eb20-"
        "111111111111111111111111"
    )

    # 개별 이벤트 ID와 추적 ID는
    # 서로 다른 역할을 해야 합니다.
    assert event["event"]["id"] != (
        event["trace"]["id"]
    )


def test_flask_http_and_application_fields():
    """
    HTTP 정보와 애플리케이션 업무 정보를
    확인합니다.
    """
    events = parse_file(SAMPLE_FILE)
    event = events[0]

    assert event["http"]["method"] == "GET"

    assert event["http"]["status_code"] == 401

    assert event["url"]["path"] == "/admin"

    assert event["application"]["service"] == (
        "security-web"
    )

    assert event["application"][
        "environment"
    ] == "production"

    assert event["application"]["level"] == (
        "WARNING"
    )

    assert event["application"]["message"] == (
        "Admin access denied"
    )


def test_flask_security_tags():
    """
    분석과 검색에 필요한 보안 태그를
    확인합니다.
    """
    events = parse_file(SAMPLE_FILE)
    event = events[0]

    assert "flask" in event["tags"]
    assert "authorization" in event["tags"]
    assert "admin_page" in event["tags"]
    assert "access_denied" in event["tags"]
    assert "warning" in event["tags"]


def test_invalid_json_raises_error():
    """
    JSON 문법이 잘못된 로그가 들어오면
    명확한 오류가 발생하는지 확인합니다.
    """
    invalid_log = (
        '{"timestamp": "2026-09-16",'
    )

    with pytest.raises(
        ValueError,
        match="올바른 JSON이 아닙니다"
    ):
        parse_line(invalid_log)


def test_missing_required_fields_raises_error():
    """
    필수 필드가 빠진 Flask 로그를
    거부하는지 확인합니다.
    """
    missing_fields_log = (
        '{'
        '"timestamp": "2026-09-16T02:00:00Z",'
        '"event_type": "authorization"'
        '}'
    )

    with pytest.raises(
        ValueError,
        match="필수 필드가 없습니다"
    ):
        parse_line(missing_fields_log)