from copy import deepcopy
from pathlib import Path

from detection.rule_engine import detect_events
from parsers.cloudtrail_parser import parse_file


PROJECT_ROOT = Path(__file__).parent.parent

SAMPLE_FILE = (
    PROJECT_ROOT
    / "samples"
    / "cloudtrail_security_group_open.json"
)

RULES_FILE = (
    PROJECT_ROOT
    / "detection"
    / "rules.yaml"
)


def test_open_ssh_rule_creates_alert():
    events = parse_file(SAMPLE_FILE)

    alerts = detect_events(
        events,
        RULES_FILE
    )

    assert len(alerts) == 1


def test_alert_has_correct_rule():
    events = parse_file(SAMPLE_FILE)

    alerts = detect_events(
        events,
        RULES_FILE
    )

    alert = alerts[0]

    assert alert["event"]["kind"] == "alert"
    assert alert["event"]["severity"] == 90
    assert alert["event"]["risk_score"] == 95

    assert alert["rule"]["id"] == "AWS-SG-001"

    assert alert["rule"]["name"] == (
        "SSH 포트 전체 인터넷 공개"
    )


def test_alert_has_security_tags():
    events = parse_file(SAMPLE_FILE)

    alerts = detect_events(
        events,
        RULES_FILE
    )

    alert = alerts[0]

    assert "critical" in alert["tags"]

    assert (
        "ssh_open_to_world"
        in alert["tags"]
    )


def test_port_443_does_not_create_ssh_alert():
    events = parse_file(SAMPLE_FILE)

    changed_event = deepcopy(events[0])

    changed_event["destination"]["port"] = 443

    alerts = detect_events(
        [changed_event],
        RULES_FILE
    )

    assert len(alerts) == 0