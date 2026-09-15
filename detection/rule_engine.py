from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml


def load_rules(
    rules_path: str | Path
) -> list[dict[str, Any]]:
    """
    YAML 파일에서 탐지 규칙을 읽습니다.
    """
    path = Path(rules_path)

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:
        rule_data = yaml.safe_load(file)

    return rule_data.get("rules", [])


def get_nested_value(
    event: dict[str, Any],
    field_path: str
) -> Any:
    """
    event.action처럼 점으로 연결된 필드를 찾습니다.
    """
    value: Any = event

    for key in field_path.split("."):
        if not isinstance(value, dict):
            return None

        value = value.get(key)

    return value


def matches_rule(
    event: dict[str, Any],
    rule: dict[str, Any]
) -> bool:
    """
    이벤트가 규칙의 모든 조건과 일치하는지 확인합니다.
    """
    conditions = rule.get("conditions", {})

    for field_path, expected_value in conditions.items():
        actual_value = get_nested_value(
            event,
            field_path
        )

        if actual_value != expected_value:
            return False

    return True


def create_alert(
    event: dict[str, Any],
    rule: dict[str, Any]
) -> dict[str, Any]:
    """
    원본 정규화 이벤트를 복사하여 보안 경보로 만듭니다.
    """
    alert = deepcopy(event)

    alert["event"]["kind"] = "alert"
    alert["event"]["severity"] = rule.get(
        "severity",
        0
    )
    alert["event"]["risk_score"] = rule.get(
        "risk_score",
        0
    )

    alert["rule"] = {
        "id": rule.get("id"),
        "name": rule.get("name"),
        "description": rule.get(
            "description"
        ),
        "recommendation": rule.get(
            "recommendation"
        )
    }

    existing_tags = alert.get("tags", [])
    rule_tags = rule.get("tags", [])

    alert["tags"] = list(
        dict.fromkeys(
            existing_tags + rule_tags
        )
    )

    return alert


def detect_events(
    events: list[dict[str, Any]],
    rules_path: str | Path
) -> list[dict[str, Any]]:
    """
    전체 이벤트를 전체 규칙과 비교합니다.
    """
    rules = load_rules(rules_path)
    alerts = []

    for event in events:
        for rule in rules:
            if matches_rule(event, rule):
                alerts.append(
                    create_alert(event, rule)
                )

    return alerts