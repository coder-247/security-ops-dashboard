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

def is_high_risk_endpoint_alert(
    alert: dict[str, Any]
) -> bool:
    """
    사건으로 승격할 Windows 엔드포인트 경보인지
    확인합니다.
    """
    event_data = alert.get("event") or {}
    log_data = alert.get("log") or {}

    return (
        event_data.get("kind") == "alert"
        and log_data.get("source")
        == "windows_sysmon"
        and event_data.get(
            "risk_score",
            0
        ) >= 80
    )


def create_endpoint_incident(
    alert: dict[str, Any]
) -> dict[str, Any]:
    """
    High 위험도의 Windows 엔드포인트 경보를
    단독 보안 사건으로 변환합니다.
    """
    event_data = alert.get("event") or {}
    log_data = alert.get("log") or {}
    rule_data = alert.get("rule") or {}
    host_data = alert.get("host") or {}
    user_data = alert.get("user") or {}
    process_data = alert.get("process") or {}

    parent_process = (
        process_data.get("parent")
        or {}
    )

    event_id = str(
        event_data.get("id", "")
    )

    host_name = host_data.get("name")
    user_name = user_data.get("name")
    user_domain = user_data.get("domain")
    process_name = process_data.get("name")

    if user_domain and user_name:
        full_user_name = (
            f"{user_domain}\\{user_name}"
        )
    else:
        full_user_name = user_name

    title = (
        rule_data.get("name")
        or "Windows 엔드포인트 보안 경보"
    )

    summary = (
        f"{host_name or '알 수 없는 호스트'}에서 "
        f"{full_user_name or '알 수 없는 사용자'}가 "
        f"{process_name or '알 수 없는 프로세스'}를 "
        "실행했습니다."
    )

    timestamp = alert.get("@timestamp")

    return {
        "incident_id": create_incident_id(
            f"endpoint:{event_id}"
        ),
        "title": title,
        "summary": summary,
        "status": "new",
        "assignee": None,
        "first_seen": timestamp,
        "last_seen": timestamp,
        "severity": event_data.get(
            "severity",
            0
        ),
        "severity_label": event_data.get(
            "severity_label",
            "informational"
        ),
        "risk_score": event_data.get(
            "risk_score",
            0
        ),
        "correlation": {
            "type": "high_risk_endpoint_alert",
            "value": event_id
        },
        "source_ips": [],
        "log_sources": [
            log_data.get("source")
        ],
        "rule_ids": [
            rule_data.get("id")
        ],
        "hosts": (
            [host_name]
            if host_name
            else []
        ),
        "users": (
            [full_user_name]
            if full_user_name
            else []
        ),
        "processes": (
            [process_name]
            if process_name
            else []
        ),
        "event_count": 1,
        "alert_count": 1,
        "recommendation": rule_data.get(
            "recommendation"
        ),
        "timeline": [
            {
                "@timestamp": timestamp,
                "event_id": event_id,
                "log_source": log_data.get(
                    "source"
                ),
                "host_name": host_name,
                "user_name": full_user_name,
                "action": event_data.get(
                    "action"
                ),
                "outcome": event_data.get(
                    "outcome"
                ),
                "process_name": process_name,
                "process_id": process_data.get(
                    "pid"
                ),
                "command_line": (
                    process_data.get(
                        "command_line"
                    )
                ),
                "parent_process_name": (
                    parent_process.get("name")
                )
            }
        ]
    }

def correlate_events(
    events: list[dict[str, Any]],
    alerts: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    1. 같은 trace.id를 가진 서로 다른 로그 출처가
       2개 이상이면 연관 사건을 생성합니다.

    2. 위험점수 80점 이상의 Windows Sysmon 경보는
       단독 엔드포인트 사건으로 승격합니다.
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

    linked_event_ids = {
        timeline_event.get("event_id")
        for incident in incidents
        for timeline_event in incident.get(
            "timeline",
            []
        )
    }

    for alert in alerts:
        event_id = (
            alert.get("event", {})
            .get("id")
        )

        if event_id in linked_event_ids:
            continue

        if not is_high_risk_endpoint_alert(
            alert
        ):
            continue

        endpoint_incident = (
            create_endpoint_incident(
                alert
            )
        )

        incidents.append(
            endpoint_incident
        )

        linked_event_ids.add(event_id)

    return incidents