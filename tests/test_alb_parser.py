from pathlib import Path

import pytest

from parsers.alb_parser import (
    parse_file,
    parse_line
)


PROJECT_ROOT = Path(__file__).parent.parent

SAMPLE_FILE = (
    PROJECT_ROOT
    / "samples"
    / "alb_admin_access.log"
)


def test_alb_file_contains_one_event():
    """
    ALB 샘플 파일에서 이벤트 1건을 읽는지 확인합니다.
    """
    events = parse_file(SAMPLE_FILE)

    assert len(events) == 1


def test_alb_source_and_destination():
    """
    접속자와 대상 서버의 IP 및 포트를 확인합니다.
    """
    events = parse_file(SAMPLE_FILE)
    event = events[0]

    assert event["source"]["ip"] == (
        "203.0.113.50"
    )

    assert event["source"]["port"] == 52341

    assert event["destination"]["ip"] == (
        "10.0.2.15"
    )

    assert event["destination"]["port"] == 80


def test_alb_http_request_and_url():
    """
    HTTP 메서드와 요청 URL이 정상적으로
    분리되는지 확인합니다.
    """
    events = parse_file(SAMPLE_FILE)
    event = events[0]

    assert event["http"]["method"] == "GET"

    assert event["http"]["version"] == (
        "HTTP/1.1"
    )

    assert event["url"]["full"] == (
        "https://security.example.com:443/admin"
    )

    assert event["url"]["path"] == "/admin"
    assert event["url"]["query"] is None


def test_alb_status_code_and_outcome():
    """
    401 상태코드가 실패 결과로 변환되는지 확인합니다.
    """
    events = parse_file(SAMPLE_FILE)
    event = events[0]

    assert event["http"]["status_code"] == 401

    assert event["http"]["target_status_code"] == (
        401
    )

    assert event["event"]["outcome"] == "failure"

    assert "client_error" in event["tags"]
    assert "admin_page" in event["tags"]


def test_alb_response_time_calculation():
    """
    세 처리시간의 합이 22ms인지 확인합니다.

    0.001초 + 0.020초 + 0.001초
    = 0.022초
    = 22ms
    """
    events = parse_file(SAMPLE_FILE)
    event = events[0]

    assert event["http"]["response_time_ms"] == (
        22.0
    )


def test_alb_cloud_trace_and_parser():
    """
    AWS ALB 자원과 추적 ID 및 파서 정보를 확인합니다.
    """
    events = parse_file(SAMPLE_FILE)
    event = events[0]

    assert event["cloud"]["provider"] == "aws"

    assert event["cloud"]["service"] == (
        "elasticloadbalancing"
    )

    assert event["cloud"]["resource_id"] == (
        "app/security-alb/50dc6c495c0c9188"
    )

    assert event["trace"]["id"] == (
        "Root=1-68c8eb20-"
        "111111111111111111111111"
    )

    assert event["parser"]["name"] == (
        "alb_parser"
    )

    assert event["parser"]["version"] == "1.0.0"
    assert event["parser"]["status"] == "success"


def test_invalid_alb_log_raises_error():
    """
    필드가 부족한 잘못된 ALB 로그가 들어오면
    오류가 발생하는지 확인합니다.
    """
    invalid_log = (
        "https 2026-09-16T02:00:00Z "
        "invalid-log"
    )

    with pytest.raises(
        ValueError,
        match="ALB 로그 필드가 부족합니다"
    ):
        parse_line(invalid_log)