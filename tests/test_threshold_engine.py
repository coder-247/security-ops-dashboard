from copy import deepcopy
from pathlib import Path

from detection.threshold_engine import (
    detect_threshold_events
)
from parsers.linux_auth_parser import (
    parse_file
)


PROJECT_ROOT = Path(__file__).parent.parent

SAMPLE_FILE = (
    PROJECT_ROOT
    / "samples"
    / "linux_auth_failed.log"
)

RULES_FILE = (
    PROJECT_ROOT
    / "detection"
    / "threshold_rules.yaml"
)


def test_five_failures_create_one_alert():
    events = parse_file(SAMPLE_FILE)

    alerts = detect_threshold_events(
        events,
        RULES_FILE
    )

    assert len(alerts) == 1


def test_ssh_alert_is_high_risk():
    events = parse_file(SAMPLE_FILE)

    alerts = detect_threshold_events(
        events,
        RULES_FILE
    )

    alert = alerts[0]

    assert alert["rule"]["id"] == (
        "LINUX-SSH-001"
    )

    assert alert["event"]["action"] == (
        "ssh_brute_force"
    )

    assert alert["event"]["severity_label"] == (
        "high"
    )

    assert alert["event"]["risk_score"] == 80


def test_alert_contains_aggregation_information():
    events = parse_file(SAMPLE_FILE)

    alerts = detect_threshold_events(
        events,
        RULES_FILE
    )

    aggregation = alerts[0]["aggregation"]

    assert aggregation["group_by"] == (
        "source.ip"
    )

    assert aggregation["group_value"] == (
        "198.51.100.25"
    )

    assert aggregation["event_count"] == 5
    assert aggregation["threshold"] == 5

    assert aggregation[
        "time_window_seconds"
    ] == 300


def test_four_failures_do_not_create_alert():
    events = parse_file(SAMPLE_FILE)

    alerts = detect_threshold_events(
        events[:4],
        RULES_FILE
    )

    assert len(alerts) == 0


def test_events_from_different_ips_do_not_combine():
    events = parse_file(SAMPLE_FILE)
    changed_events = deepcopy(events)

    changed_events[-1]["source"]["ip"] = (
        "198.51.100.99"
    )

    alerts = detect_threshold_events(
        changed_events,
        RULES_FILE
    )

    assert len(alerts) == 0


def test_events_outside_five_minutes_do_not_alert():
    events = parse_file(SAMPLE_FILE)
    changed_events = deepcopy(events)

    changed_events[-1]["@timestamp"] = (
        "2026-09-16T02:20:57Z"
    )

    alerts = detect_threshold_events(
        changed_events,
        RULES_FILE
    )

    assert len(alerts) == 0