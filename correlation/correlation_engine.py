import hashlib
from typing import Any


SEVERITY_ORDER = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}


def get_trace_id(
    event: dict[str, Any]
) -> str | None:
    trace = event.get("trace") or {}
    trace_id = trace.get("id")

    if not trace_id or trace_id == "-":
        return None

    return str(trace_id)


def create_incident_id(trace_id: str) -> str:
    """
    trace.id를 이용해 동일한 사건 ID를 만듭니다.
    """
    digest = hashlib.sha256(
        trace_id.encode("utf-8")
    ).hexdigest()[:12].upper()

    return f"INC-{digest}"


def group_events_by_trace(
    events: list[dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    """
    같은 trace.id를 가진 이벤트끼리 묶습니다.
    """
    groups: dict[
        str,
        list[dict[str, Any]]
    ] = {}

    for event in events:
        trace_id = get_trace_id(event)

        if trace_id is None:
            continue

        groups.setdefault(
            trace_id,
            []
        ).append(event)

    return groups


def find_linked_alerts(
    events: list[dict[str, Any]],
    alerts: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    묶인 이벤트와 관련된 보안 경보를 찾습니다.
    """
    event_ids = {
        event.get("event", {}).get("id")
        for event in events
    }

    return [
        alert
        for alert in alerts
        if alert.get("event", {}).get("id")
        in event_ids
    ]


def get_highest_alert(
    alerts: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """
    연결된 경보 중 위험점수가 가장 높은 경보를 찾습니다.
    """
    if not alerts:
        return None

    return max(
        alerts,
        key=lambda alert: (
            alert
            .get("event", {})
            .get("risk_score", 0)
        )
    )


def create_timeline(
    events: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    대시보드에 표시할 시간순 로그 목록을 만듭니다.
    """
    sorted_events = sorted(
        events,
        key=lambda event: event.get(
            "@timestamp",
            ""
        )
    )

    timeline = []

    for event in sorted_events:
        event_data = event.get("event") or {}
        log_data = event.get("log") or {}
        source_data = event.get("source") or {}
        http_data = event.get("http") or {}
        url_data = event.get("url") or {}

        timeline.append(
            {
                "@timestamp": event.get(
                    "@timestamp"
                ),
                "event_id": event_data.get("id"),
                "log_source": log_data.get(
                    "source"
                ),
                "source_ip": source_data.get(
                    "ip"
                ),
                "action": event_data.get(
                    "action"
                ),
                "outcome": event_data.get(
                    "outcome"
                ),
                "http_status_code": (
                    http_data.get("status_code")
                ),
                "url_path": url_data.get(
                    "path"
                )
            }
        )

    return timeline


def create_incident(
    trace_id: str,
    events: list[dict[str, Any]],
    alerts: list[dict[str, Any]]
) -> dict[str, Any]:
    """
    연관된 여러 이벤트를 하나의 사건으로 만듭니다.
    """
    sorted_events = sorted(
        events,
        key=lambda event: event.get(
            "@timestamp",
            ""
        )
    )

    linked_alerts = find_linked_alerts(
        events,
        alerts
    )

    highest_alert = get_highest_alert(
        linked_alerts
    )

    log_sources = sorted({
        event.get("log", {}).get("source")
        for event in events
        if event.get("log", {}).get("source")
    })

    source_ips = sorted({
        event.get("source", {}).get("ip")
        for event in events
        if event.get("source", {}).get("ip")
    })

    rule_ids = sorted({
        alert.get("rule", {}).get("id")
        for alert in linked_alerts
        if alert.get("rule", {}).get("id")
    })

    if highest_alert:
        highest_event = highest_alert.get(
            "event",
            {}
        )

        highest_rule = highest_alert.get(
            "rule",
            {}
        )

        severity = highest_event.get(
            "severity",
            0
        )

        severity_label = highest_event.get(
            "severity_label",
            "informational"
        )

        risk_score = highest_event.get(
            "risk_score",
            0
        )

        recommendation = highest_rule.get(
            "recommendation"
        )

    else:
        severity = 0
        severity_label = "informational"
        risk_score = 0
        recommendation = None

    source_text = " → ".join(log_sources)

    return {
        "incident_id": create_incident_id(
            trace_id
        ),
        "title": "관리자 페이지 접근 연관 이벤트",
        "summary": (
            f"{len(events)}개 로그에서 "
            f"동일 요청이 확인되었습니다: "
            f"{source_text}"
        ),
        "status": "new",
        "assignee": None,
        "first_seen": sorted_events[0].get(
            "@timestamp"
        ),
        "last_seen": sorted_events[-1].get(
            "@timestamp"
        ),
        "severity": severity,
        "severity_label": severity_label,
        "risk_score": risk_score,
        "correlation": {
            "type": "trace_id",
            "value": trace_id
        },
        "source_ips": source_ips,
        "log_sources": log_sources,
        "rule_ids": rule_ids,
        "event_count": len(events),
        "alert_count": len(linked_alerts),
        "recommendation": recommendation,
        "timeline": create_timeline(events)
    }


def correlate_events(
    events: list[dict[str, Any]],
    alerts: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    같은 trace.id를 가진 서로 다른 로그 출처가
    2개 이상일 때 하나의 사건을 생성합니다.
    """
    grouped_events = group_events_by_trace(
        events
    )

    incidents = []

    for trace_id, grouped in grouped_events.items():
        log_sources = {
            event.get("log", {}).get("source")
            for event in grouped
        }

        valid_sources = {
            source
            for source in log_sources
            if source
        }

        if len(valid_sources) < 2:
            continue

        incident = create_incident(
            trace_id,
            grouped,
            alerts
        )

        incidents.append(incident)

    return incidents