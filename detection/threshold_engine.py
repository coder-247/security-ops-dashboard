import hashlib
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from detection.rule_engine import (
    get_nested_value
)


def load_threshold_rules(
    rules_path: str | Path
) -> list[dict[str, Any]]:
    path = Path(rules_path)

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:
        rule_data = yaml.safe_load(file)

    if not isinstance(rule_data, dict):
        return []

    return rule_data.get(
        "threshold_rules",
        []
    )


def parse_timestamp(
    timestamp_text: str
) -> datetime:
    """
    2026-09-16T02:10:01Z 형식을
    시간 계산이 가능한 datetime으로 바꿉니다.
    """
    normalized_timestamp = (
        timestamp_text.replace(
            "Z",
            "+00:00"
        )
    )

    return datetime.fromisoformat(
        normalized_timestamp
    )


def event_matches_conditions(
    event: dict[str, Any],
    conditions: dict[str, Any]
) -> bool:
    """
    이벤트가 임계치 규칙의 기본 조건과
    모두 일치하는지 확인합니다.
    """
    for field_path, expected_value in (
        conditions.items()
    ):
        actual_value = get_nested_value(
            event,
            field_path
        )

        if actual_value != expected_value:
            return False

    return True


def filter_matching_events(
    events: list[dict[str, Any]],
    rule: dict[str, Any]
) -> list[dict[str, Any]]:
    conditions = rule.get(
        "conditions",
        {}
    )

    return [
        event
        for event in events
        if event_matches_conditions(
            event,
            conditions
        )
    ]


def group_events(
    events: list[dict[str, Any]],
    group_by: str
) -> dict[str, list[dict[str, Any]]]:
    """
    source.ip처럼 규칙에서 지정한 필드를 기준으로
    이벤트를 묶습니다.
    """
    groups: dict[
        str,
        list[dict[str, Any]]
    ] = {}

    for event in events:
        group_value = get_nested_value(
            event,
            group_by
        )

        if group_value is None:
            continue

        group_key = str(group_value)

        groups.setdefault(
            group_key,
            []
        ).append(event)

    return groups


def find_threshold_window(
    events: list[dict[str, Any]],
    threshold: int,
    time_window_seconds: int
) -> list[dict[str, Any]] | None:
    """
    시간순으로 이벤트를 확인하면서 지정된 시간 안에
    임계 횟수가 발생했는지 찾습니다.
    """
    timed_events = []

    for event in events:
        timestamp_text = event.get(
            "@timestamp"
        )

        if not timestamp_text:
            continue

        try:
            event_time = parse_timestamp(
                timestamp_text
            )

        except ValueError:
            continue

        timed_events.append(
            (event_time, event)
        )

    timed_events.sort(
        key=lambda item: item[0]
    )

    left_index = 0

    for right_index in range(
        len(timed_events)
    ):
        while left_index <= right_index:
            time_difference = (
                timed_events[right_index][0]
                - timed_events[left_index][0]
            ).total_seconds()

            if (
                time_difference
                <= time_window_seconds
            ):
                break

            left_index += 1

        event_count = (
            right_index
            - left_index
            + 1
        )

        if event_count >= threshold:
            return [
                item[1]
                for item in timed_events[
                    left_index:right_index + 1
                ]
            ]

    return None


def create_alert_id(
    rule_id: str,
    group_value: str,
    first_seen: str,
    last_seen: str
) -> str:
    source_text = (
        f"{rule_id}|"
        f"{group_value}|"
        f"{first_seen}|"
        f"{last_seen}"
    )

    digest = hashlib.sha256(
        source_text.encode("utf-8")
    ).hexdigest()[:16]

    return f"ALERT-{digest.upper()}"


def create_threshold_alert(
    event_window: list[dict[str, Any]],
    rule: dict[str, Any],
    group_value: str
) -> dict[str, Any]:
    """
    임계치에 도달한 이벤트 묶음을
    하나의 보안 경보로 만듭니다.
    """
    first_event = event_window[0]
    last_event = event_window[-1]

    first_seen = first_event["@timestamp"]
    last_seen = last_event["@timestamp"]

    alert = deepcopy(last_event)

    alert["event"]["id"] = create_alert_id(
        rule.get("id", "unknown"),
        group_value,
        first_seen,
        last_seen
    )

    alert["event"]["kind"] = "alert"

    alert["event"]["action"] = rule.get(
        "alert_action",
        "threshold_exceeded"
    )

    alert["event"]["severity"] = rule.get(
        "severity",
        0
    )

    alert["event"]["severity_label"] = rule.get(
        "severity_label",
        "informational"
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

    existing_tags = alert.get(
        "tags",
        []
    )

    rule_tags = rule.get(
        "tags",
        []
    )

    alert["tags"] = list(
        dict.fromkeys(
            existing_tags + rule_tags
        )
    )

    alert["aggregation"] = {
        "group_by": rule.get("group_by"),
        "group_value": group_value,
        "event_count": len(event_window),
        "threshold": rule.get("threshold"),
        "time_window_seconds": rule.get(
            "time_window_seconds"
        ),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "event_ids": [
            event["event"]["id"]
            for event in event_window
        ]
    }

    return alert


def detect_threshold_events(
    events: list[dict[str, Any]],
    rules_path: str | Path
) -> list[dict[str, Any]]:
    """
    모든 임계치 규칙을 전체 이벤트에 적용합니다.
    """
    rules = load_threshold_rules(
        rules_path
    )

    alerts = []

    for rule in rules:
        matching_events = filter_matching_events(
            events,
            rule
        )

        group_by = rule.get("group_by")

        if not group_by:
            continue

        grouped_events = group_events(
            matching_events,
            group_by
        )

        threshold = int(
            rule.get("threshold", 1)
        )

        time_window_seconds = int(
            rule.get(
                "time_window_seconds",
                300
            )
        )

        for group_value, group in (
            grouped_events.items()
        ):
            event_window = find_threshold_window(
                group,
                threshold,
                time_window_seconds
            )

            if event_window is None:
                continue

            alert = create_threshold_alert(
                event_window,
                rule,
                group_value
            )

            alerts.append(alert)

    return alerts