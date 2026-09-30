from copy import deepcopy
from pathlib import Path

from correlation.correlation_engine import (
    correlate_events
)
from detection.rule_engine import (
    detect_events
)
from parsers.sysmon_parser import (
    parse_file
)


PROJECT_ROOT = Path(__file__).parent.parent

RULES_FILE = (
    PROJECT_ROOT
    / "detection"
    / "rules.yaml"
)

SYSMON_SAMPLE_FILE = (
    PROJECT_ROOT
    / "samples"
    / "sysmon_suspicious_powershell.json"
)


def create_sysmon_data():
    events = parse_file(
        SYSMON_SAMPLE_FILE
    )

    alerts = detect_events(
        events,
        RULES_FILE
    )

    return events, alerts


def test_sysmon_alert_creates_incident():
    events, alerts = create_sysmon_data()

    incidents = correlate_events(
        events,
        alerts
    )

    assert len(incidents) == 1


def test_sysmon_incident_risk_and_status():
    events, alerts = create_sysmon_data()

    incident = correlate_events(
        events,
        alerts
    )[0]

    assert incident["status"] == "new"
    assert incident["severity_label"] == "high"
    assert incident["risk_score"] == 90

    assert incident[
        "correlation"
    ]["type"] == (
        "high_risk_endpoint_alert"
    )

    assert incident["rule_ids"] == [
        "WIN-SYSMON-001"
    ]


def test_sysmon_incident_endpoint_fields():
    events, alerts = create_sysmon_data()

    incident = correlate_events(
        events,
        alerts
    )[0]

    assert incident["hosts"] == [
        "WIN-ENDPOINT-01"
    ]

    assert incident["users"] == [
        "LAB\\student"
    ]

    assert incident["processes"] == [
        "powershell.exe"
    ]

    timeline = incident["timeline"][0]

    assert timeline["process_name"] == (
        "powershell.exe"
    )

    assert timeline[
        "parent_process_name"
    ] == "cmd.exe"

    assert "-EncodedCommand" in (
        timeline["command_line"]
    )


def test_low_risk_sysmon_alert_not_incident():
    events, alerts = create_sysmon_data()

    low_risk_alert = deepcopy(
        alerts[0]
    )

    low_risk_alert[
        "event"
    ]["risk_score"] = 79

    incidents = correlate_events(
        events,
        [low_risk_alert]
    )

    assert incidents == []