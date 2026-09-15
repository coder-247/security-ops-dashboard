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