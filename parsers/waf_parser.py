import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PARSER_NAME = "waf_parser"
PARSER_VERSION = "1.0.0"


def convert_timestamp(timestamp_ms: int) -> str:
    """
    WAF의 밀리초 시간을 ISO 8601 UTC 시간으로 변환합니다.

    예:
    1789520400000
    → 2026-09-16T01:00:00Z
    """
    if not isinstance(timestamp_ms, int):
        raise ValueError(
            "WAF timestamp가 정수가 아닙니다."
        )

    timestamp_seconds = timestamp_ms / 1000

    converted_time = datetime.fromtimestamp(
        timestamp_seconds,
        tz=timezone.utc
    )

    return (
        converted_time
        .isoformat()
        .replace("+00:00", "Z")
    )


def create_event_id(record: dict[str, Any]) -> str:
    """
    WAF requestId를 이벤트 ID로 사용합니다.
    requestId가 없으면 원본 내용으로 해시를 만듭니다.
    """
    http_request = record.get("httpRequest") or {}
    request_id = http_request.get("requestId")

    if request_id:
        return request_id

    original_log = json.dumps(
        record,
        sort_keys=True,
        ensure_ascii=False
    )

    return hashlib.sha256(
        original_log.encode("utf-8")
    ).hexdigest()


def get_header(
    headers: list[dict[str, Any]],
    header_name: str
) -> str | None:
    """
    HTTP 헤더 목록에서 원하는 값을 찾습니다.
    대문자와 소문자는 구분하지 않습니다.
    """
    for header in headers:
        name = str(
            header.get("name", "")
        ).lower()

        if name == header_name.lower():
            return header.get("value")

    return None


def get_terminating_rule(
    record: dict[str, Any]
) -> dict[str, Any]:
    """
    WAF Rule Group 안에서 실제로 요청을 종료한 규칙을 찾습니다.
    """
    rule_groups = record.get(
        "ruleGroupList"
    ) or []

    for rule_group in rule_groups:
        terminating_rule = rule_group.get(
            "terminatingRule"
        )

        if terminating_rule:
            return terminating_rule

    return {}


def get_attack_type(
    record: dict[str, Any],
    terminating_rule: dict[str, Any]
) -> str | None:
    """
    WAF 규칙 일치 정보에서 공격 유형을 찾습니다.
    """
    match_details = record.get(
        "terminatingRuleMatchDetails"
    ) or []

    if match_details:
        condition_type = match_details[0].get(
            "conditionType"
        )

        if condition_type:
            return condition_type

    rule_id = str(
        terminating_rule.get("ruleId", "")
    ).upper()

    if "SQLI" in rule_id:
        return "SQL_INJECTION"

    if "XSS" in rule_id:
        return "XSS"

    return None


def get_region(web_acl_id: str) -> str | None:
    """
    WAF ARN에서 리전을 꺼냅니다.

    arn:aws:wafv2:ap-northeast-2:...
    """
    arn_parts = web_acl_id.split(":")

    if len(arn_parts) > 3:
        return arn_parts[3]

    return None


def create_tags(
    action: str,
    attack_type: str | None
) -> list[str]:
    """
    WAF 이벤트의 기본 태그를 만듭니다.
    """
    tags = [
        "aws",
        "waf",
        "web_security"
    ]

    if action == "BLOCK":
        tags.append("blocked")

    elif action == "ALLOW":
        tags.append("allowed")

    if attack_type == "SQL_INJECTION":
        tags.append("sql_injection")

    elif attack_type == "XSS":
        tags.append("xss")

    return tags


def parse_record(record: dict[str, Any]) -> dict[str, Any]:
    """
    WAF 로그 한 건을 공통 로그 형식으로 변환합니다.
    """
    http_request = record.get(
        "httpRequest"
    ) or {}

    headers = http_request.get(
        "headers"
    ) or []

    action = str(
        record.get("action", "UNKNOWN")
    ).upper()

    terminating_rule = get_terminating_rule(
        record
    )

    attack_type = get_attack_type(
        record,
        terminating_rule
    )

    terminating_rule_id = (
        terminating_rule.get("ruleId")
        or record.get("terminatingRuleId")
    )

    web_acl_id = str(
        record.get("webaclId", "")
    )

    event_outcome = {
        "BLOCK": "blocked",
        "ALLOW": "allowed",
        "CAPTCHA": "challenged",
        "CHALLENGE": "challenged"
    }.get(
        action,
        "unknown"
    )

    return {
        "@timestamp": convert_timestamp(
            record.get("timestamp")
        ),
        "schema_version": "1.0.0",
        "event": {
            "id": create_event_id(record),
            "kind": "event",
            "category": "web",
            "action": action.lower(),
            "outcome": event_outcome,
            "severity": 0,
            "severity_label": "informational",
            "risk_score": 0
        },
        "log": {
            "source": "aws_waf",
            "original": json.dumps(
                record,
                ensure_ascii=False
            )
        },
        "source": {
            "ip": http_request.get("clientIp"),
            "port": None,
            "cidr": None
        },
        "destination": {
            "ip": None,
            "port": 443
            if http_request.get("scheme") == "https"
            else 80,
            "service": str(
                record.get(
                    "httpSourceName",
                    "unknown"
                )
            ).lower()
        },
        "network": {
            "transport": "tcp"
        },
        "user": {
            "name": None
        },
        "http": {
            "method": http_request.get(
                "httpMethod"
            ),
            "status_code": record.get(
                "responseCodeSent"
            ),
            "user_agent": get_header(
                headers,
                "user-agent"
            )
        },
        "url": {
            "path": http_request.get("uri"),
            "query": http_request.get("args")
        },
        "cloud": {
            "provider": "aws",
            "service": "waf",
            "region": get_region(web_acl_id),
            "resource_id": web_acl_id
        },
        "rule": {
            "id": terminating_rule_id,
            "name": record.get(
                "terminatingRuleId"
            ),
            "description": None,
            "recommendation": None
        },
        "parser": {
            "name": PARSER_NAME,
            "version": PARSER_VERSION,
            "status": "success"
        },
        "tags": create_tags(
            action,
            attack_type
        )
    }


def parse_file(
    file_path: str | Path
) -> list[dict[str, Any]]:
    """
    WAF JSON 파일을 읽어 공통 이벤트 목록으로 반환합니다.
    """
    path = Path(file_path)

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:
        waf_data = json.load(file)

    if isinstance(waf_data, list):
        records = waf_data
    elif isinstance(waf_data, dict):
        records = [waf_data]
    else:
        raise ValueError(
            "WAF 로그는 JSON 객체 또는 배열이어야 합니다."
        )

    return [
        parse_record(record)
        for record in records
    ]