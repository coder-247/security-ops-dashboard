import json
from pathlib import Path

import pytest

from parsers.parser_router import (
    detect_log_type,
    parse_auto
)
from parsers.sysmon_parser import (
    parse_event,
    parse_file
)


PROJECT_ROOT = Path(__file__).parent.parent

SYSMON_SAMPLE_FILE = (
    PROJECT_ROOT
    / "samples"
    / "sysmon_suspicious_powershell.json"
)


def test_sysmon_file_contains_one_event():
    events = parse_file(
        SYSMON_SAMPLE_FILE
    )

    assert len(events) == 1


def test_sysmon_common_fields():
    event = parse_file(
        SYSMON_SAMPLE_FILE
    )[0]

    assert event["@timestamp"] == (
        "2026-09-29T10:30:00Z"
    )

    assert len(event["event"]["id"]) == 64

    assert event["event"]["category"] == (
        "process"
    )

    assert event["event"]["action"] == (
        "process_start"
    )

    assert event["log"]["source"] == (
        "windows_sysmon"
    )

    assert event["host"]["name"] == (
        "WIN-ENDPOINT-01"
    )


def test_sysmon_process_information():
    event = parse_file(
        SYSMON_SAMPLE_FILE
    )[0]

    process = event["process"]

    assert process["pid"] == 4321
    assert process["name"] == "powershell.exe"

    assert process["executable"].endswith(
        "powershell.exe"
    )

    assert "-EncodedCommand" in (
        process["command_line"]
    )

    assert process["parent"]["pid"] == 1234

    assert process["parent"]["name"] == (
        "cmd.exe"
    )


def test_sysmon_user_and_hash():
    event = parse_file(
        SYSMON_SAMPLE_FILE
    )[0]

    assert event["user"]["domain"] == "LAB"
    assert event["user"]["name"] == "student"

    sha256 = (
        event["process"]["hash"]["sha256"]
    )

    assert len(sha256) == 64


def test_sysmon_security_tags():
    event = parse_file(
        SYSMON_SAMPLE_FILE
    )[0]

    tags = event["tags"]

    assert "windows" in tags
    assert "endpoint" in tags
    assert "edr" in tags
    assert "sysmon" in tags
    assert "powershell" in tags
    assert "encoded_command" in tags

    assert "suspicious_powershell" in tags


def test_sysmon_invalid_event_id():
    invalid_event = {
        "@timestamp": "2026-09-29T10:30:00Z",
        "winlog": {
            "event_id": 3,
            "event_data": {}
        }
    }

    with pytest.raises(
        ValueError,
        match="Event ID 1"
    ):
        parse_event(invalid_event)


def test_invalid_sysmon_json(tmp_path):
    invalid_file = (
        tmp_path
        / "invalid_sysmon.json"
    )

    invalid_file.write_text(
        "{ invalid json",
        encoding="utf-8"
    )

    with pytest.raises(
        ValueError,
        match="올바르지 않은 Sysmon JSON"
    ):
        parse_file(invalid_file)


def test_router_detects_sysmon():
    detected_type = detect_log_type(
        SYSMON_SAMPLE_FILE
    )

    assert detected_type == "sysmon"


def test_router_parses_sysmon():
    events = parse_auto(
        SYSMON_SAMPLE_FILE
    )

    assert len(events) == 1

    assert events[0]["log"]["source"] == (
        "windows_sysmon"
    )