from copy import deepcopy
from pathlib import Path

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


def get_sysmon_alerts(
    events: list[dict]
) -> list[dict]:
    alerts = detect_events(
        events,
        RULES_FILE
    )

    return [
        alert
        for alert in alerts
        if alert["rule"]["id"]
        == "WIN-SYSMON-001"
    ]


def test_encoded_powershell_creates_alert():
    events = parse_file(
        SYSMON_SAMPLE_FILE
    )

    alerts = get_sysmon_alerts(events)

    assert len(alerts) == 1


def test_sysmon_alert_has_high_risk():
    events = parse_file(
        SYSMON_SAMPLE_FILE
    )

    alert = get_sysmon_alerts(
        events
    )[0]

    assert alert["event"]["kind"] == (
        "alert"
    )

    assert alert["event"]["severity"] == 70

    assert alert[
        "event"
    ]["severity_label"] == "high"

    assert alert["event"]["risk_score"] == 90

    assert alert["rule"]["id"] == (
        "WIN-SYSMON-001"
    )

    assert "edr" in alert["tags"]

    assert "suspicious_powershell" in (
        alert["tags"]
    )


def test_normal_powershell_does_not_alert():
    events = parse_file(
        SYSMON_SAMPLE_FILE
    )

    normal_event = deepcopy(events[0])

    normal_event[
        "process"
    ]["command_line"] = (
        'powershell.exe Write-Host "hello"'
    )

    alerts = get_sysmon_alerts(
        [normal_event]
    )

    assert alerts == []


def test_contains_condition_is_case_insensitive():
    events = parse_file(
        SYSMON_SAMPLE_FILE
    )

    event = deepcopy(events[0])

    event[
        "process"
    ]["command_line"] = (
        "powershell.exe "
        "-encodedcommand TEST"
    )

    alerts = get_sysmon_alerts(
        [event]
    )

    assert len(alerts) == 1