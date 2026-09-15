import json
from pathlib import Path

from correlation.correlation_engine import (
    correlate_events
)
from detection.rule_engine import detect_events
from detection.threshold_engine import (
    detect_threshold_events
)   
from parsers.parser_router import (
    detect_log_type,
    parse_auto
)


INPUT_FILES = [
    Path("samples/cloudtrail_security_group_open.json"),
    Path("samples/waf_sql_injection_block.json"),
    Path("samples/alb_admin_access.log"),
    Path("samples/nginx_admin_access.log"),
    Path("samples/linux_auth_failed.log")
]

RULES_FILE = Path(
    "detection/rules.yaml"
)

THRESHOLD_RULES_FILE = Path(
    "detection/threshold_rules.yaml"
)

EVENT_OUTPUT_FILE = Path(
    "outputs/normalized/security_events.jsonl"
)

ALERT_OUTPUT_FILE = Path(
    "outputs/alerts/security_alerts.jsonl"
)

INCIDENT_OUTPUT_FILE = Path(
    "outputs/incidents/security_incidents.jsonl"
)


def save_jsonl(
    items: list[dict],
    output_file: Path
) -> None:
    output_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with output_file.open(
        "w",
        encoding="utf-8"
    ) as file:
        for item in items:
            json_line = json.dumps(
                item,
                ensure_ascii=False
            )

            file.write(json_line + "\n")


def collect_and_parse() -> list[dict]:
    all_events = []

    for input_file in INPUT_FILES:
        log_type = detect_log_type(
            input_file
        )

        print(
            f"    {input_file.name} "
            f"→ {log_type}"
        )

        events = parse_auto(
            input_file
        )

        all_events.extend(events)

    return all_events


def main() -> None:
    print("[1] 로그 종류 자동 판별")

    events = collect_and_parse()

    print(
        f"[2] 전체 정규화 이벤트: "
        f"{len(events)}건"
    )

    save_jsonl(
        events,
        EVENT_OUTPUT_FILE
    )

    print("[3] 탐지 규칙 적용")

    single_event_alerts = detect_events(
    events,
    RULES_FILE
)

    print(
        f"    단일 이벤트 경보: "
        f"{len(single_event_alerts)}건"
    )

    threshold_alerts = detect_threshold_events(
        events,
        THRESHOLD_RULES_FILE
    )

    print(
        f"    임계치 경보: "
        f"{len(threshold_alerts)}건"
    )

    alerts = (
        single_event_alerts
        + threshold_alerts
    )
    save_jsonl(
        alerts,
        ALERT_OUTPUT_FILE
    )

    print(
        f"[4] 생성된 보안 경보: "
        f"{len(alerts)}건"
    )

    print("[5] 연관분석 실행")

    incidents = correlate_events(
        events,
        alerts
    )

    save_jsonl(
        incidents,
        INCIDENT_OUTPUT_FILE
    )

    print(
        f"[6] 생성된 보안 사건: "
        f"{len(incidents)}건"
    )

    print(
        f"[7] 이벤트 저장: "
        f"{EVENT_OUTPUT_FILE}"
    )

    print(
        f"[8] 경보 저장: "
        f"{ALERT_OUTPUT_FILE}"
    )

    print(
        f"[9] 사건 저장: "
        f"{INCIDENT_OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()