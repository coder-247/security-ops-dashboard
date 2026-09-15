from copy import deepcopy
from pathlib import Path

from correlation.correlation_engine import (
    correlate_events
)
from detection.rule_engine import detect_events
from parsers.alb_parser import (
    parse_file as parse_alb_file
)
from parsers.nginx_parser import (
    parse_file as parse_nginx_file
)


PROJECT_ROOT = Path(__file__).parent.parent

ALB_SAMPLE_FILE = (
    PROJECT_ROOT
    / "samples"
    / "alb_admin_access.log"
)

NGINX_SAMPLE_FILE = (
    PROJECT_ROOT
    / "samples"
    / "nginx_admin_access.log"
)

RULES_FILE = (
    PROJECT_ROOT
    / "detection"
    / "rules.yaml"
)


def create_test_data():
    alb_events = parse_alb_file(
        ALB_SAMPLE_FILE
    )

    nginx_events = parse_nginx_file(
        NGINX_SAMPLE_FILE
    )

    events = alb_events + nginx_events

    alerts = detect_events(
        events,
        RULES_FILE
    )

    return events, alerts


def test_same_trace_creates_one_incident():
    events, alerts = create_test_data()

    incidents = correlate_events(
        events,
        alerts
    )

    assert len(incidents) == 1


def test_incident_contains_trace_id():
    events, alerts = create_test_data()

    incidents = correlate_events(
        events,
        alerts
    )

    incident = incidents[0]

    assert incident["correlation"]["type"] == (
        "trace_id"
    )

    assert incident["correlation"]["value"] == (
        "Root=1-68c8eb20-"
        "111111111111111111111111"
    )


def test_incident_contains_two_log_sources():
    events, alerts = create_test_data()

    incidents = correlate_events(
        events,
        alerts
    )

    incident = incidents[0]

    assert incident["event_count"] == 2

    assert set(incident["log_sources"]) == {
        "aws_alb",
        "nginx_access"
    }


def test_incident_uses_highest_alert_score():
    events, alerts = create_test_data()

    incidents = correlate_events(
        events,
        alerts
    )

    incident = incidents[0]

    assert incident["severity"] == 50

    assert incident["severity_label"] == (
        "medium"
    )

    assert incident["risk_score"] == 60

    assert incident["rule_ids"] == [
        "ALB-ADMIN-001"
    ]


def test_incident_timeline_contains_two_events():
    events, alerts = create_test_data()

    incidents = correlate_events(
        events,
        alerts
    )

    timeline = incidents[0]["timeline"]

    assert len(timeline) == 2

    timeline_sources = {
        item["log_source"]
        for item in timeline
    }

    assert timeline_sources == {
        "aws_alb",
        "nginx_access"
    }


def test_different_trace_ids_do_not_correlate():
    events, alerts = create_test_data()

    changed_events = deepcopy(events)

    changed_events[1]["trace"]["id"] = (
        "different-trace-id"
    )

    incidents = correlate_events(
        changed_events,
        alerts
    )

    assert len(incidents) == 0