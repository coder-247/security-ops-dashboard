from pathlib import Path

import pytest

from parsers.alb_parser import (
    parse_file as parse_alb_file
)
from parsers.nginx_parser import (
    parse_file as parse_nginx_file,
    parse_line
)


PROJECT_ROOT = Path(__file__).parent.parent

NGINX_SAMPLE_FILE = (
    PROJECT_ROOT
    / "samples"
    / "nginx_admin_access.log"
)

ALB_SAMPLE_FILE = (
    PROJECT_ROOT
    / "samples"
    / "alb_admin_access.log"
)


def test_nginx_file_contains_one_event():
    events = parse_nginx_file(
        NGINX_SAMPLE_FILE
    )

    assert len(events) == 1


def test_nginx_timestamp_converts_to_utc():
    events = parse_nginx_file(
        NGINX_SAMPLE_FILE
    )

    event = events[0]

    assert event["@timestamp"] == (
        "2026-09-16T02:00:00Z"
    )


def test_nginx_source_and_user():
    events = parse_nginx_file(
        NGINX_SAMPLE_FILE
    )

    event = events[0]

    assert event["source"]["ip"] == (
        "203.0.113.50"
    )

    assert event["user"]["name"] is None


def test_nginx_http_and_url_fields():
    events = parse_nginx_file(
        NGINX_SAMPLE_FILE
    )

    event = events[0]

    assert event["http"]["method"] == "GET"

    assert event["http"]["version"] == (
        "HTTP/1.1"
    )

    assert event["http"]["status_code"] == 401

    assert event["http"]["user_agent"] == (
        "security-test-client/1.0"
    )

    assert event["url"]["path"] == "/admin"
    assert event["url"]["query"] is None


def test_nginx_response_time_and_tags():
    events = parse_nginx_file(
        NGINX_SAMPLE_FILE
    )

    event = events[0]

    assert event["http"]["response_bytes"] == (
        182
    )

    assert event["http"]["response_time_ms"] == (
        45.0
    )

    assert "nginx" in event["tags"]
    assert "client_error" in event["tags"]
    assert "admin_page" in event["tags"]

    assert (
        "authentication_failure"
        in event["tags"]
    )


def test_nginx_and_alb_trace_ids_match():
    """
    같은 요청을 나타내는 ALB와 Nginx 로그의
    추적 ID가 일치하는지 확인합니다.
    """
    nginx_events = parse_nginx_file(
        NGINX_SAMPLE_FILE
    )

    alb_events = parse_alb_file(
        ALB_SAMPLE_FILE
    )

    nginx_trace_id = (
        nginx_events[0]["trace"]["id"]
    )

    alb_trace_id = (
        alb_events[0]["trace"]["id"]
    )

    assert nginx_trace_id is not None
    assert nginx_trace_id == alb_trace_id


def test_nginx_parser_information():
    events = parse_nginx_file(
        NGINX_SAMPLE_FILE
    )

    event = events[0]

    assert event["log"]["source"] == (
        "nginx_access"
    )

    assert event["parser"]["name"] == (
        "nginx_parser"
    )

    assert event["parser"]["version"] == "1.0.0"
    assert event["parser"]["status"] == "success"


def test_invalid_nginx_log_raises_error():
    invalid_log = (
        '203.0.113.50 invalid nginx log'
    )

    with pytest.raises(
        ValueError,
        match="지원하지 않는 Nginx 로그 형식"
    ):
        parse_line(invalid_log)