from pathlib import Path

from parsers.cloudtrail_parser import parse_file


PROJECT_ROOT = Path(__file__).parent.parent

SAMPLE_FILE = (
    PROJECT_ROOT
    / "samples"
    / "cloudtrail_security_group_open.json"
)


def test_cloudtrail_file_contains_one_event():
    events = parse_file(SAMPLE_FILE)

    assert len(events) == 1


def test_cloudtrail_common_fields():
    events = parse_file(SAMPLE_FILE)
    event = events[0]

    assert event["@timestamp"] == (
        "2026-09-15T10:00:00Z"
    )

    assert event["log"]["source"] == (
        "aws_cloudtrail"
    )

    assert event["event"]["action"] == (
        "AuthorizeSecurityGroupIngress"
    )

    assert event["event"]["outcome"] == "success"


def test_cloudtrail_user_and_source():
    events = parse_file(SAMPLE_FILE)
    event = events[0]

    assert event["user"]["name"] == "test-user"

    assert event["source"]["ip"] == (
        "203.0.113.10"
    )


def test_security_group_information():
    events = parse_file(SAMPLE_FILE)
    event = events[0]

    assert event["source"]["cidr"] == (
        "0.0.0.0/0"
    )

    assert event["destination"]["port"] == 22

    assert event["network"]["transport"] == (
        "tcp"
    )

    assert event["cloud"]["resource_id"] == (
        "sg-0123456789abcdef0"
    )


def test_cloudtrail_parser_information():
    events = parse_file(SAMPLE_FILE)
    event = events[0]

    assert event["parser"]["name"] == (
        "cloudtrail_parser"
    )

    assert event["parser"]["version"] == "1.1.0"
    assert event["parser"]["status"] == "success"