from pathlib import Path

import pytest

from parsers.parser_router import (
    UnsupportedLogFormatError,
    detect_log_type,
    parse_auto
)


PROJECT_ROOT = Path(__file__).parent.parent

CLOUDTRAIL_FILE = (
    PROJECT_ROOT
    / "samples"
    / "cloudtrail_security_group_open.json"
)

WAF_FILE = (
    PROJECT_ROOT
    / "samples"
    / "waf_sql_injection_block.json"
)

ALB_FILE = (
    PROJECT_ROOT
    / "samples"
    / "alb_admin_access.log"
)

NGINX_FILE = (
    PROJECT_ROOT
    / "samples"
    / "nginx_admin_access.log"
)


def test_detects_cloudtrail_log():
    log_type = detect_log_type(
        CLOUDTRAIL_FILE
    )

    assert log_type == "cloudtrail"


def test_detects_waf_log():
    log_type = detect_log_type(
        WAF_FILE
    )

    assert log_type == "waf"


def test_automatically_parses_cloudtrail():
    events = parse_auto(
        CLOUDTRAIL_FILE
    )

    assert len(events) == 1

    assert events[0]["log"]["source"] == (
        "aws_cloudtrail"
    )


def test_automatically_parses_waf():
    events = parse_auto(
        WAF_FILE
    )

    assert len(events) == 1

    assert events[0]["log"]["source"] == (
        "aws_waf"
    )


def test_unknown_log_raises_error(
    tmp_path: Path
):
    unknown_file = (
        tmp_path
        / "unknown.json"
    )

    unknown_file.write_text(
        '{"message": "unknown log"}',
        encoding="utf-8"
    )

    with pytest.raises(
        UnsupportedLogFormatError
    ):
        detect_log_type(unknown_file)

def test_detects_alb_log():
    log_type = detect_log_type(
        ALB_FILE
    )

    assert log_type == "alb"


def test_automatically_parses_alb():
    events = parse_auto(
        ALB_FILE
    )

    assert len(events) == 1

    event = events[0]

    assert event["log"]["source"] == "aws_alb"
    assert event["source"]["ip"] == "203.0.113.50"
    assert event["url"]["path"] == "/admin"
    assert event["http"]["status_code"] == 401

def test_detects_nginx_log():
    log_type = detect_log_type(
        NGINX_FILE
    )

    assert log_type == "nginx"


def test_automatically_parses_nginx():
    events = parse_auto(
        NGINX_FILE
    )

    assert len(events) == 1

    event = events[0]

    assert event["log"]["source"] == (
        "nginx_access"
    )

    assert event["source"]["ip"] == (
        "203.0.113.50"
    )

    assert event["url"]["path"] == "/admin"

    assert event["http"]["status_code"] == 401

    assert event["parser"]["name"] == (
        "nginx_parser"
    )