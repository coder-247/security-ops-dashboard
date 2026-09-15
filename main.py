import json
from datetime import datetime, timezone
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
from storage.quarantine import (
    create_failure_record,
    load_failure_records,
    merge_failure_records,
    save_failure_records
)

from storage.elasticsearch_storage import (
    ElasticsearchStorage,
)


INPUT_FILES = [
    Path("samples/cloudtrail_security_group_open.json"),
    Path("samples/waf_sql_injection_block.json"),
    Path("samples/alb_admin_access.log"),
    Path("samples/nginx_admin_access.log"),
    Path("samples/linux_auth_failed.log"),
    Path("samples/flask_application.jsonl"),
    Path("samples/nginx_with_invalid_line.log"),
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

QUARANTINE_OUTPUT_FILE = Path(
    "outputs/quarantine/failed_logs.jsonl"
)

STATISTICS_OUTPUT_FILE = Path(
    "outputs/metrics/parsing_statistics.json"
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

def save_json(
    data: dict,
    output_file: Path
) -> None:
    """
    통계 데이터를 일반 JSON 파일로 저장합니다.
    """
    output_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with output_file.open(
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            data,
            file,
            ensure_ascii=False,
            indent=2
        )

def collect_and_parse() -> tuple[
    list[dict],
    list[dict],
    dict
]:
    """
    파일별로 파싱을 시도합니다.

    한 파일이 실패해도 다음 파일을 계속 처리합니다.
    """
    all_events = []
    failure_records = []

    statistics = {
        "total_files": len(INPUT_FILES),
        "successful_files": 0,
        "failed_files": 0,
        "total_events": 0,
        "parse_success_rate": 0.0
    }

    for input_file in INPUT_FILES:
        detected_log_type = "unknown"

        try:
            detected_log_type = detect_log_type(
                input_file
            )

            print(
                f"    {input_file.name} "
                f"→ {detected_log_type}"
            )

            events = parse_auto(
                input_file
            )

            all_events.extend(events)

            statistics[
                "successful_files"
            ] += 1

            statistics[
                "total_events"
            ] += len(events)

        except Exception as error:
            statistics[
                "failed_files"
            ] += 1

            failure_record = (
                create_failure_record(
                    input_file,
                    error,
                    detected_log_type
                )
            )

            failure_records.append(
                failure_record
            )

            print(
                f"    {input_file.name} "
                f"→ 파싱 실패·격리"
            )

            print(
                f"      원인: {error}"
            )

    total_files = statistics["total_files"]

    if total_files > 0:
        statistics["parse_success_rate"] = round(
            (
                statistics["successful_files"]
                / total_files
            )
            * 100,
            2
        )
        statistics["parse_failure_rate"] = round(
        (
            statistics["failed_files"]
            / total_files
        )
        * 100,
        2
    )

    else:
        statistics["parse_failure_rate"] = 0.0

    statistics["generated_at"] = (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    return (
        all_events,
        failure_records,
        statistics
    )

def save_to_elasticsearch(
    events: list[dict],
    alerts: list[dict],
    incidents: list[dict],
    statistics: dict,
) -> None:
    """
    처리 결과를 Elasticsearch에 저장합니다.

    Elasticsearch가 꺼져 있어도 기존 JSONL 저장 결과는
    유지되고 프로그램 전체가 중단되지 않습니다.
    """
    storage = ElasticsearchStorage()

    try:
        if not storage.is_available():
            print(
                "    Elasticsearch 연결 실패: "
                "JSONL 파일만 저장합니다."
            )
            return

        storage.ensure_indices()

        event_count = storage.save_documents(
            "security-events",
            events,
        )

        alert_count = storage.save_documents(
            "security-alerts",
            alerts,
        )

        incident_count = storage.save_documents(
            "security-incidents",
            incidents,
        )

        metric_count = storage.save_documents(
            "parser-metrics",
            [statistics],
        )

        print(
            f"    이벤트: {event_count}건"
        )
        print(
            f"    경보: {alert_count}건"
        )
        print(
            f"    사건: {incident_count}건"
        )
        print(
            f"    파싱 통계: {metric_count}건"
        )

    except Exception as error:
        print(
            "    Elasticsearch 저장 실패: "
            f"{error}"
        )
        print(
            "    기존 JSONL 파일은 정상적으로 "
            "유지됩니다."
        )

    finally:
        storage.close()

def main() -> None:
    print("[1] 로그 종류 자동 판별 및 파싱")

    (
        events,
        failure_records,
        statistics
    ) = collect_and_parse()

    print(
        f"[2] 전체 정규화 이벤트: "
        f"{len(events)}건"
    )

    print(
        f"    성공 파일: "
        f"{statistics['successful_files']}개"
    )

    print(
        f"    실패 파일: "
        f"{statistics['failed_files']}개"
    )

    print(
        f"    파싱 성공률: "
        f"{statistics['parse_success_rate']}%"
    )

    existing_failure_records = (
        load_failure_records(
            QUARANTINE_OUTPUT_FILE
        )
    )

    merged_failure_records = (
        merge_failure_records(
            existing_failure_records,
            failure_records
        )
    )

    save_failure_records(
        merged_failure_records,
        QUARANTINE_OUTPUT_FILE
    )

    save_jsonl(
        merged_failure_records,
        QUARANTINE_OUTPUT_FILE
    )

    save_json(
        statistics,
        STATISTICS_OUTPUT_FILE
    )

    save_jsonl(
        events,
        EVENT_OUTPUT_FILE,
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
        f"[7] 격리된 실패 로그: "
        f"{len(failure_records)}건"
    )

    print(
        f"[8] 이벤트 저장: "
        f"{EVENT_OUTPUT_FILE}"
    )

    print(
        f"[9] 경보 저장: "
        f"{ALERT_OUTPUT_FILE}"
    )

    print(
        f"[10] 사건 저장: "
        f"{INCIDENT_OUTPUT_FILE}"
    )

    print(
        f"[11] 실패 로그 저장: "
        f"{QUARANTINE_OUTPUT_FILE}"
    )

    print(
        f"[12] 파싱 통계 저장: "
        f"{STATISTICS_OUTPUT_FILE}"
    )
    print(
    f"    격리 목록의 고유 실패 로그: "
    f"{len(merged_failure_records)}건"
)

    print("[13] Elasticsearch 저장")

    save_to_elasticsearch(
        events,
        alerts,
        incidents,
        statistics,
    )

if __name__ == "__main__":
    main()