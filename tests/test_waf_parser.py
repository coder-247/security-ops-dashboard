from copy import deepcopy
from pathlib import Path

from detection.rule_engine import detect_events
from parsers.waf_parser import parse_file


PROJECT_ROOT = Path(__file__).parent.parent

SAMPLE_FILE = (
    PROJECT_ROOT
    / "samples"
    / "waf_sql_injection_block.json"
)

RULES_FILE = (
    PROJECT_ROOT
    / "detection"
    / "rules.yaml"
)


def test_waf_file_contains_one_event():
    """
    샘플 WAF 파일에서 이벤트 1건을 읽는지 확인합니다.
    """
    events = parse_file(SAMPLE_FILE)

    assert len(events) == 1


def test_waf_timestamp_and_source_ip():
    """
    밀리초 시간이 UTC 시간으로 변환되고
    공격자 IP가 정상 추출되는지 확인합니다.
    """
    events = parse_file(SAMPLE_FILE)
    event = events[0]

    assert event["@timestamp"] == (
        "2026-09-16T01:00:00Z"
    )

    assert event["source"]["ip"] == (
        "203.0.113.50"
    )

    assert event["log"]["source"] == "aws_waf"


def test_waf_http_and_url_fields():
    """
    HTTP 요청 정보와 URL이 정상 추출되는지 확인합니다.
    """
    events = parse_file(SAMPLE_FILE)
    event = events[0]

    assert event["http"]["method"] == "GET"
    assert event["http"]["status_code"] == 403

    assert event["http"]["user_agent"] == (
        "security-test-client/1.0"
    )

    assert event["url"]["path"] == "/search"

    assert event["url"]["query"] == (
        "q=' OR 1=1--"
    )


def test_waf_action_rule_and_tags():
    """
    WAF 차단 결과, 탐지 규칙, 보안 태그를 확인합니다.
    """
    events = parse_file(SAMPLE_FILE)
    event = events[0]

    assert event["event"]["category"] == "web"
    assert event["event"]["action"] == "block"
    assert event["event"]["outcome"] == "blocked"

    assert event["rule"]["id"] == (
        "SQLi_QUERYARGUMENTS"
    )

    assert "waf" in event["tags"]
    assert "blocked" in event["tags"]
    assert "sql_injection" in event["tags"]


def test_waf_parser_information():
    """
    어떤 파서와 버전으로 처리됐는지 확인합니다.
    """
    events = parse_file(SAMPLE_FILE)
    event = events[0]

    assert event["parser"]["name"] == "waf_parser"
    assert event["parser"]["version"] == "1.0.0"
    assert event["parser"]["status"] == "success"


def test_waf_sql_injection_creates_high_alert():
    """
    SQL Injection 차단 이벤트가 High 85점 경보로
    변환되는지 확인합니다.
    """
    events = parse_file(SAMPLE_FILE)

    alerts = detect_events(
        events,
        RULES_FILE
    )

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert["event"]["kind"] == "alert"
    assert alert["event"]["severity"] == 70

    assert alert["event"]["severity_label"] == (
        "high"
    )

    assert alert["event"]["risk_score"] == 85

    assert alert["rule"]["id"] == "WAF-SQLI-001"

    assert alert["rule"]["name"] == (
        "AWS WAF SQL Injection 차단"
    )

    assert "high" in alert["tags"]
    assert "web_attack" in alert["tags"]
    assert "sql_injection" in alert["tags"]


def test_allowed_request_does_not_create_sqli_alert():
    """
    WAF가 허용한 요청에서는 SQL Injection 차단 경보가
    생성되지 않는지 확인합니다.
    """
    events = parse_file(SAMPLE_FILE)

    allowed_event = deepcopy(events[0])

    allowed_event["event"]["action"] = "allow"
    allowed_event["event"]["outcome"] = "allowed"

    alerts = detect_events(
        [allowed_event],
        RULES_FILE
    )

    assert len(alerts) == 0